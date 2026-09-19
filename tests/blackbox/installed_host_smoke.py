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
one existing UDS listener. With --rollback-python it also runs the bounded
Rust → Python → Rust state and behavior sequence described in
docs/state-compatibility.md.
"""

from __future__ import annotations

import argparse
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
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA = 1
COMMAND_TIMEOUT = 20.0
OUTPUT_LIMIT = 4_096
JSON_LIMIT = 4 * 1024 * 1024
PARTIAL_STATUS = "partial_unexecuted"
AGENT_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
ROLLBACK_ORIGIN_HOST = "127.0.0.2"
ROLLBACK_ACTIVATION_TIMEOUT = 5.0


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
        return Path(os.path.abspath(selected)) if selected else None
    interpreter = Path(fields[0])
    return Path(os.path.abspath(os.fspath(interpreter))) if interpreter.is_file() else None


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
            package_location = Path(package.stdout.strip()[-OUTPUT_LIMIT:]).expanduser()
            try:
                package_path = package_location.resolve(strict=True)
            except (FileNotFoundError, OSError) as exc:
                raise SmokeError(
                    f"selected CLI interpreter reported an unusable safeyolo package: {package_location}"
                ) from exc
            result["package_location"] = str(package_path)
        else:
            raise SmokeError("selected CLI interpreter could not import an installed safeyolo package")
    else:
        raise SmokeError("selected CLI launcher has no usable Python shebang interpreter")
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
    return (path if path.is_absolute() else cwd / path).resolve()


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


def _select_backend(config_dir: Path, backend: str) -> bytes:
    """Atomically select one backend in the disposable installed config.

    This helper intentionally changes only ``proxy.backend``. The smoke lane
    uses a caller-created disposable directory, so preserving the original
    bytes lets a failed rollback be diagnosed without rewriting unrelated
    policy, listener, or service state.
    """
    if backend not in {"python", "rust"}:
        raise ValueError(f"unsupported proxy backend: {backend}")
    path = config_dir / "config.yaml"
    original = path.read_bytes()
    try:
        import yaml
    except ImportError as exc:
        raise SmokeError("PyYAML is required to select an installed proxy backend") from exc
    try:
        config = yaml.safe_load(original.decode("utf-8")) or {}
    except (UnicodeError, OSError, yaml.YAMLError) as exc:
        raise SmokeError(f"installed CLI config is missing or malformed: {path}") from exc
    if not isinstance(config, dict) or not isinstance(config.get("proxy"), dict):
        raise SmokeError("installed CLI config has no proxy mapping")
    config["proxy"]["backend"] = backend
    temporary = path.with_name(f".{path.name}.rollback.tmp")
    mode = path.stat().st_mode & 0o777
    try:
        temporary.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        temporary.chmod(mode)
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise SmokeError(f"unable to select proxy.backend: {backend}") from exc
    return original


def _restore_config(config_dir: Path, original: bytes) -> None:
    """Restore the caller's disposable selector after a rollback probe."""
    path = config_dir / "config.yaml"
    mode = path.stat().st_mode & 0o777
    temporary = path.with_name(f".{path.name}.rollback.restore.tmp")
    try:
        temporary.write_bytes(original)
        temporary.chmod(mode)
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise SmokeError(f"unable to restore the disposable installed config: {path}") from exc


def _admin_request(
    native: dict[str, Any],
    *,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    """Use the running native operator API without retaining its bearer token."""
    readiness = _read_json(Path(native["readiness_file"]), "Rust readiness marker")
    port = readiness.get("admin_port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise SmokeError("native rollback control has no published admin port")
    token_value = native["raw"].get("admin_api_token_file")
    if not isinstance(token_value, str) or not token_value:
        raise SmokeError("native rollback control has no admin token file")
    token_path = Path(token_value).expanduser()
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, OSError, UnicodeError) as exc:
        raise SmokeError("native rollback control cannot read its admin token") from exc
    if not token or any(char in token for char in "\r\n"):
        raise SmokeError("native rollback control has an empty or malformed admin token")
    encoded = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {token}"}
    if encoded is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        body = response.read(JSON_LIMIT)
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise SmokeError(f"native rollback control request failed: {method} {path}") from exc
    finally:
        connection.close()
    try:
        value: Any = json.loads(body) if body else None
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SmokeError(f"native rollback control returned non-JSON: {method} {path}") from exc
    return status, value


def _proxy_status(socket_path: str, url: str) -> int:
    """Drive one ordinary HTTP request through an installed proxy UDS."""
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.netloc:
        raise SmokeError(f"rollback probe URL must be an HTTP URL: {url}")
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
        raise SmokeError(f"installed rollback HTTP probe failed for {url}") from exc
    first_line = bytes(response).split(b"\r\n", 1)[0].split()
    if len(first_line) < 2:
        raise SmokeError(f"installed rollback HTTP probe returned no status for {url}")
    try:
        return int(first_line[1])
    except ValueError as exc:
        raise SmokeError(f"installed rollback HTTP probe returned an invalid status for {url}") from exc


def _poll_proxy_allowed(socket_path: str, url: str) -> float:
    """Wait for the policy watcher to publish an allowed endpoint, for at most 5s."""
    started = time.monotonic()
    deadline = started + ROLLBACK_ACTIVATION_TIMEOUT
    last_status: int | None = None
    last_error: SmokeError | None = None
    while True:
        try:
            last_status = _proxy_status(socket_path, url)
            last_error = None
            if last_status == 200:
                return time.monotonic() - started
        except SmokeError as exc:
            last_error = exc
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            detail = f"HTTP {last_status}" if last_status is not None else str(last_error)
            raise SmokeError(
                f"installed rollback policy watcher did not allow {url} within "
                f"{ROLLBACK_ACTIVATION_TIMEOUT:.1f}s ({detail})"
            )
        time.sleep(min(0.05, remaining))


def _rollback_origin() -> tuple[http.server.ThreadingHTTPServer, threading.Thread]:
    """Provide an owned local origin for the allowed behavior check."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
            body = b"rollback-origin-ok\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = http.server.ThreadingHTTPServer((ROLLBACK_ORIGIN_HOST, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, name="safeyolo-rollback-origin", daemon=True)
    thread.start()
    return server, thread


def _write_native_rollback_state(native: dict[str, Any], origin_port: int) -> dict[str, Any]:
    """Write one supported host policy through native's authenticated writer."""
    allow_endpoint = f"{ROLLBACK_ORIGIN_HOST}:{origin_port}"
    allow_status, allow_body = _admin_request(
        native,
        method="POST",
        path="/admin/policy/host/allow",
        payload={"host": ROLLBACK_ORIGIN_HOST, "port": origin_port, "rate": 60},
    )
    deny_status, deny_body = _admin_request(
        native,
        method="POST",
        path="/admin/policy/host/deny",
        payload={"host": "rollback-denied.invalid"},
    )
    if allow_status != 200 or deny_status != 200:
        raise SmokeError(
            f"native rollback policy writes failed: allow HTTP {allow_status}, deny HTTP {deny_status}"
        )
    read_status, baseline = _admin_request(
        native, method="GET", path="/admin/policy/baseline"
    )
    if read_status != 200:
        raise SmokeError(f"native rollback policy read failed: HTTP {read_status}")
    policy_value = native["raw"].get("policy_file")
    if not isinstance(policy_value, str) or not policy_value:
        raise SmokeError("native rollback policy has no durable policy path")
    policy_path = Path(policy_value).expanduser()
    try:
        persisted = policy_path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeError) as exc:
        raise SmokeError("native rollback policy was not durably saved") from exc
    try:
        parsed_policy = tomllib.loads(persisted)
    except tomllib.TOMLDecodeError as exc:
        raise SmokeError("native rollback policy file is not valid TOML") from exc
    hosts = parsed_policy.get("hosts")
    if not isinstance(hosts, dict) or allow_endpoint not in hosts or "rollback-denied.invalid" not in hosts:
        raise SmokeError(
            f"native rollback policy file omitted exact written host rules: {allow_endpoint}"
        )
    return {
        "allow": {"status": allow_status, "response": allow_body},
        "deny": {"status": deny_status, "response": deny_body},
        "read": {
            "status": read_status,
            "contains_written_hosts": True,
            "contains_allow_endpoint": True,
            "allow_endpoint": allow_endpoint,
        },
        "policy_sha256": _sha256(policy_path),
        "allow_endpoint": allow_endpoint,
        "origin_host": ROLLBACK_ORIGIN_HOST,
        "origin_port": origin_port,
    }


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
    """Read the actual supported-host executable, when the host exposes it."""
    if sys.platform.startswith("linux"):
        proc = Path(f"/proc/{pid}/exe")
        try:
            return proc.resolve(strict=True)
        except (FileNotFoundError, OSError):
            return None
    if platform.system() != "Darwin":
        return None
    # macOS has no /proc. `comm` is preferred, while `command` also provides
    # an absolute argv[0] on hosts whose ps does not expose it in comm.
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
    config_path: Path,
    working_directory: Path,
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
    recorded_config = receipt.get("config_file")
    if not isinstance(recorded_config, str) or not Path(recorded_config).is_absolute():
        raise SmokeError("Rust process receipt config_file must be absolute")
    if Path(recorded_config).resolve() != config_path.resolve():
        raise SmokeError("Rust process receipt config_file does not match supplied native config")
    recorded_working_directory = receipt.get("working_directory")
    if not isinstance(recorded_working_directory, str) or not Path(recorded_working_directory).is_absolute():
        raise SmokeError("Rust process receipt working_directory must be absolute")
    if Path(recorded_working_directory).resolve() != working_directory.resolve():
        raise SmokeError("Rust process receipt working_directory does not match smoke working directory")
    readiness_value = receipt.get("readiness_file")
    if not isinstance(readiness_value, str) or not Path(readiness_value).is_absolute():
        raise SmokeError("Rust process receipt readiness_file must be absolute")
    readiness_path = Path(readiness_value).resolve()
    if readiness_path != Path(native["readiness_file"]).resolve():
        raise SmokeError("Rust process receipt readiness_file does not match supplied native config")
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
    """Exercise one disposable native instance and optional Python rollback."""
    config_dir = _config_dir(args.config_dir)
    _require_disposable(config_dir)
    cwd = Path(args.working_directory).expanduser().resolve()
    cli = _cli_identity(args.cli)
    candidate_path, candidate = _rust_identity(args.rust_bin)
    config = _read_cli_yaml(config_dir)
    original_config = (config_dir / "config.yaml").read_bytes()
    configured = _configured_rust_config(config, cwd)
    supplied = _absolute_path(args.rust_config, cwd)
    if configured != supplied:
        raise SmokeError(f"CLI proxy.rust_config points to {configured}, not supplied {supplied}")
    native = _native_config(supplied, cwd)
    substrate = _substrate_identity(config_dir)
    report = _base_report(cli, candidate, substrate)
    report["instance"] = {"config_dir": str(config_dir), "mode": "smoke"}
    report["native"] = {key: value for key, value in native.items() if key != "raw"}
    try:
        _require_substrate(substrate)
        logs_dir = _smoke_logs_dir(config_dir)
    except SmokeError as exc:
        report["status"] = "infrastructure_failure"
        report["error"] = str(exc)
        return report, 2
    report["logs_dir"] = str(logs_dir)
    data_dir = config_dir / "data"
    receipt = data_dir / "proxy-rust.json"
    if receipt.exists():
        raise SmokeError(f"refusing to reuse an existing Rust process receipt: {receipt}")
    env = os.environ.copy()
    env["SAFEYOLO_CONFIG_DIR"] = str(config_dir)
    env["SAFEYOLO_LOGS_DIR"] = str(logs_dir)
    env["SAFEYOLO_LOG_PATH"] = str(logs_dir / "safeyolo.jsonl")
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
        runtime = _runtime_observation(
            config_dir,
            native,
            candidate_path,
            config_path=supplied,
            working_directory=cwd,
            require_running=True,
        )
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
    rollback_server: http.server.ThreadingHTTPServer | None = None
    rollback_thread: threading.Thread | None = None
    rollback_state: dict[str, Any] | None = None
    if args.rollback_python:
        try:
            rollback_server, rollback_thread = _rollback_origin()
            rollback_state = _write_native_rollback_state(
                native, rollback_server.server_address[1]
            )
            listener = _agent_map(config_dir)[0]["path"]
            native_allowed_wait = _poll_proxy_allowed(
                listener,
                f"http://{rollback_state['origin_host']}:{rollback_state['origin_port']}/allowed",
            )
            native_allowed_status = _proxy_status(
                listener,
                f"http://{rollback_state['origin_host']}:{rollback_state['origin_port']}/allowed",
            )
            native_denied_status = _proxy_status(
                listener, "http://rollback-denied.invalid/denied"
            )
            report["native_before_rollback"] = {
                "state": rollback_state,
                "allowed_status": native_allowed_status,
                "allowed_activation_wait_seconds": native_allowed_wait,
                "denied_status": native_denied_status,
            }
            if native_allowed_status != 200:
                raise SmokeError("native written allow rule did not permit the local origin")
            if native_denied_status != 403:
                raise SmokeError("native written deny rule did not reject the denied origin")
        except SmokeError as exc:
            if rollback_server is not None:
                rollback_server.shutdown()
                if rollback_thread is not None:
                    rollback_thread.join(timeout=5)
            cleanup = _run([str(cli_path), "stop"], env=env, cwd=cwd)
            report["commands"]["cleanup_stop"] = {
                "argv": [str(cli_path), "stop"],
                "exit": cleanup.returncode,
                "stdout_tail": cleanup.stdout,
                "stderr_tail": cleanup.stderr,
            }
            report["status"] = "rollback_failure"
            report["error"] = str(exc)
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

    if args.rollback_python:
        rollback_env = dict(env)
        rollback_env.pop("SAFEYOLO_RUST_PROXY", None)
        try:
            _select_backend(config_dir, "python")
            rollback_start = _run([str(cli_path), "start", "--wait"], env=rollback_env, cwd=cwd)
            report["commands"]["rollback_python_start"] = {
                "argv": [str(cli_path), "start", "--wait"],
                "exit": rollback_start.returncode,
                "stdout_tail": rollback_start.stdout,
                "stderr_tail": rollback_start.stderr,
            }
            if rollback_start.returncode != 0:
                raise SmokeError("installed Python rollback start failed")
            python_pid_file = config_dir / "data" / "proxy.pid"
            try:
                python_pid = int(python_pid_file.read_text(encoding="utf-8").strip())
            except (FileNotFoundError, OSError, ValueError) as exc:
                raise SmokeError("installed Python rollback did not publish proxy.pid") from exc
            if not _pid_alive(python_pid):
                raise SmokeError("installed Python rollback process is not alive")
            if rollback_state is None or rollback_server is None:
                raise SmokeError("installed rollback state was not prepared before Python selection")
            policy_show = _run(
                [str(cli_path), "policy", "show", "--section", "hosts"],
                env=rollback_env,
                cwd=cwd,
            )
            report["commands"]["rollback_python_policy_show"] = {
                "argv": [str(cli_path), "policy", "show", "--section", "hosts"],
                "exit": policy_show.returncode,
                "stdout_tail": policy_show.stdout,
                "stderr_tail": policy_show.stderr,
            }
            if policy_show.returncode != 0:
                raise SmokeError("selected Python comparator could not read effective policy")
            if "rollback-denied.invalid" not in policy_show.stdout:
                raise SmokeError("selected Python comparator omitted the native-written deny rule")
            allow_endpoint = rollback_state["allow_endpoint"]
            if allow_endpoint not in policy_show.stdout:
                raise SmokeError(
                    "selected Python comparator omitted the exact native-written allow endpoint"
                )
            listener = _agent_map(config_dir)[0]["path"]
            python_allowed_wait = _poll_proxy_allowed(
                listener,
                f"http://{rollback_state['origin_host']}:{rollback_state['origin_port']}/python",
            )
            python_allowed = _proxy_status(
                listener, f"http://{rollback_state['origin_host']}:{rollback_state['origin_port']}/python"
            )
            python_denied = _proxy_status(listener, "http://rollback-denied.invalid/python")
            if python_allowed != 200 or python_denied != 403:
                raise SmokeError(
                    "selected Python comparator did not enforce the native-written allow/deny state"
                )
            report["rollback"] = {
                "backend": "python",
                "pid": python_pid,
                "pid_alive_before_stop": True,
                "rust_receipt_exists": receipt.exists(),
                "policy_show": {
                    "exit": policy_show.returncode,
                    "contains_native_allow_and_deny": True,
                    "contains_allow_endpoint": True,
                    "allow_endpoint": allow_endpoint,
                    "representation": "source host rules; compiled deny remains default-deny",
                },
                "allowed_status": python_allowed,
                "allowed_activation_wait_seconds": python_allowed_wait,
                "denied_status": python_denied,
            }
            rollback_stop = _run([str(cli_path), "stop"], env=rollback_env, cwd=cwd)
            report["commands"]["rollback_python_stop"] = {
                "argv": [str(cli_path), "stop"],
                "exit": rollback_stop.returncode,
                "stdout_tail": rollback_stop.stdout,
                "stderr_tail": rollback_stop.stderr,
            }
            if rollback_stop.returncode != 0:
                raise SmokeError("installed Python rollback stop failed")
            if python_pid_file.exists() or _pid_alive(python_pid):
                raise SmokeError("installed Python rollback left a running process or pid file")
            report["rollback"].update(
                {"pid_alive_after_stop": _pid_alive(python_pid), "pid_file_exists": python_pid_file.exists()}
            )
            _select_backend(config_dir, "rust")
            return_start = _run(start_command, env=env, cwd=cwd)
            report["commands"]["return_rust_start"] = {
                "argv": start_command,
                "exit": return_start.returncode,
                "stdout_tail": return_start.stdout,
                "stderr_tail": return_start.stderr,
            }
            if return_start.returncode != 0:
                raise SmokeError("return to the Rust backend failed after Python rollback")
            returned_native = _native_config(supplied, cwd)
            report["return_rust_runtime"] = _runtime_observation(
                config_dir,
                returned_native,
                candidate_path,
                config_path=supplied,
                working_directory=cwd,
                require_running=True,
            )
            returned_listener = _agent_map(config_dir)[0]["path"]
            returned_health = _probe_agent_health(_agent_map(config_dir)[0], config_dir)
            returned_allowed_wait = _poll_proxy_allowed(
                returned_listener,
                f"http://{rollback_state['origin_host']}:{rollback_state['origin_port']}/returned",
            )
            returned_allowed = _proxy_status(
                returned_listener,
                f"http://{rollback_state['origin_host']}:{rollback_state['origin_port']}/returned",
            )
            returned_denied = _proxy_status(
                returned_listener, "http://rollback-denied.invalid/returned"
            )
            if returned_allowed != 200 or returned_denied != 403:
                raise SmokeError("Rust after rollback did not preserve the allowed/denied behavior")
            report["return_rust"] = {
                "health": returned_health,
                "allowed_status": returned_allowed,
                "allowed_activation_wait_seconds": returned_allowed_wait,
                "denied_status": returned_denied,
            }
            return_stop = _run(stop_command, env=env, cwd=cwd)
            report["commands"]["return_rust_stop"] = {
                "argv": stop_command,
                "exit": return_stop.returncode,
                "stdout_tail": return_stop.stdout,
                "stderr_tail": return_stop.stderr,
            }
            if return_stop.returncode != 0 or receipt.exists():
                raise SmokeError("Rust return stop did not clean its process receipt")
            report["rollback"]["status"] = "passed"
        except SmokeError as exc:
            report["status"] = "rollback_failure"
            report["error"] = str(exc)
            try:
                selected_config = _read_cli_yaml(config_dir)
                selected_backend = selected_config.get("proxy", {}).get("backend")
                cleanup_env = env if selected_backend == "rust" else rollback_env
                _run([str(cli_path), "stop"], env=cleanup_env, cwd=cwd)
            except (OSError, subprocess.SubprocessError, SmokeError):
                pass
            return report, 2
        finally:
            _restore_config(config_dir, original_config)
            if rollback_server is not None:
                rollback_server.shutdown()
                if rollback_thread is not None:
                    rollback_thread.join(timeout=5)

    report["status"] = PARTIAL_STATUS
    report["acceptance_a"] = {
        "status": "unexecuted",
        "reason": (
            "host UDS health completed, but guest isolation and authenticated "
            "runtime identity are unavailable"
        ),
    }
    return report, 2


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
    parser.add_argument(
        "--rollback-python",
        action="store_true",
        help="write native host state, select Python, verify 200/403 behavior, then return to Rust",
    )
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
