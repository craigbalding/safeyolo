"""Collision-safe lifecycle helpers for Tailscale Serve mappings."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

TAILSCALE_READY_TIMEOUT_SECONDS = 15
TAILSCALE_OPERATION_TIMEOUT_SECONDS = 40


class TailnetServeError(RuntimeError):
    """A Tailscale Serve mapping could not be inspected or managed."""


def normalize_display_path(path: str) -> str:
    """Return an absolute browser path without changing query or fragment."""
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


def validate_tailnet_port(port: int) -> None:
    if type(port) is not int or port < 1 or port > 65535:
        raise ValueError("tailnet HTTPS port must be 1-65535")


def run_tailscale_json(*args: str) -> dict:
    """Run a read-only Tailscale JSON command and validate its response."""
    try:
        result = subprocess.run(
            ["tailscale", *args],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except FileNotFoundError as exc:
        raise TailnetServeError("Tailscale is not installed; install and connect Tailscale first") from exc
    except subprocess.TimeoutExpired as exc:
        raise TailnetServeError(f"tailscale {' '.join(args)} timed out") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        suffix = f": {detail}" if detail else ""
        raise TailnetServeError(f"tailscale {' '.join(args)} failed{suffix}")
    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise TailnetServeError(f"tailscale {' '.join(args)} returned invalid JSON") from exc
    if payload is None and args == ("serve", "status", "--json"):
        return {}
    if not isinstance(payload, dict):
        raise TailnetServeError(f"tailscale {' '.join(args)} returned unexpected JSON")
    return payload


def node_serve_configs(status: dict):
    """Yield node-level background and foreground configs, not Services."""
    yield status
    foreground = status.get("Foreground", {})
    if isinstance(foreground, dict):
        for config in foreground.values():
            if isinstance(config, dict):
                yield config


def tailnet_port_in_use(status: dict, port: int) -> bool:
    for config in node_serve_configs(status):
        tcp = config.get("TCP", {})
        if isinstance(tcp, dict) and str(port) in tcp:
            return True
    return False


def tailnet_mapping_ready(status: dict, port: int, target: str) -> bool:
    """Return whether *port* is mapped to the exact loopback target."""

    def contains_exact(value) -> bool:
        if value == target:
            return True
        if isinstance(value, dict):
            return any(contains_exact(child) for child in value.values())
        if isinstance(value, list):
            return any(contains_exact(child) for child in value)
        return False

    for config in node_serve_configs(status):
        tcp = config.get("TCP", {})
        if not isinstance(tcp, dict) or str(port) not in tcp:
            continue
        web = config.get("Web", {})
        if isinstance(web, dict) and contains_exact(web):
            return True
    return False


def tailnet_identity() -> str:
    """Return the connected node's MagicDNS name."""
    if shutil.which("tailscale") is None:
        raise TailnetServeError("Tailscale is not installed; install and connect Tailscale first")
    node_status = run_tailscale_json("status", "--json")
    if node_status.get("BackendState") != "Running":
        state = node_status.get("BackendState", "unknown")
        raise TailnetServeError(f"Tailscale is not connected (state: {state})")
    self_status = node_status.get("Self")
    dns_name = self_status.get("DNSName", "") if isinstance(self_status, dict) else ""
    dns_name = str(dns_name).rstrip(".")
    if not dns_name:
        raise TailnetServeError("Tailscale status did not report a MagicDNS name")
    return dns_name


def tailnet_url(dns_name: str, port: int, display_path: str = "/") -> str:
    authority = dns_name if port == 443 else f"{dns_name}:{port}"
    return f"https://{authority}{normalize_display_path(display_path)}"


def preflight_tailnet_serve(
    exposed_port: int,
    *,
    allow_target: str | None = None,
) -> str:
    """Validate node state and refuse replacement of an existing mapping."""
    validate_tailnet_port(exposed_port)
    dns_name = tailnet_identity()
    serve_status = run_tailscale_json("serve", "status", "--json")
    if tailnet_port_in_use(serve_status, exposed_port):
        if allow_target and tailnet_mapping_ready(serve_status, exposed_port, allow_target):
            return dns_name
        raise TailnetServeError(
            f"tailnet HTTPS port {exposed_port} already has a Tailscale Serve mapping; choose another port"
        )
    return dns_name


@dataclass
class TailnetServeSession:
    """One foreground Tailscale Serve mapping owned by its caller."""

    process: subprocess.Popen[str]
    dns_name: str
    exposed_port: int
    target: str
    output: TextIO | None = None
    closing: bool = False

    def url(self, display_path: str = "/") -> str:
        return tailnet_url(self.dns_name, self.exposed_port, display_path)

    def close(self) -> None:
        if self.process.poll() is None:
            self.closing = True
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.close_output()

    def read_output(self) -> str:
        stream = self.output or self.process.stdout
        if stream is None:
            return ""
        try:
            stream.flush()
            stream.seek(0)
            return stream.read().strip()
        except (OSError, ValueError):
            return ""

    def close_output(self) -> None:
        streams = [self.output, self.process.stdout]
        for stream in streams:
            if stream is not None and not stream.closed:
                stream.close()


def start_tailnet_serve(local_port: int, exposed_port: int) -> TailnetServeSession:
    """Publish one loopback service through foreground Tailscale Serve."""
    dns_name = preflight_tailnet_serve(exposed_port)
    target = f"http://127.0.0.1:{local_port}"
    command = [
        "tailscale",
        "serve",
        "--yes",
        f"--https={exposed_port}",
        target,
    ]
    output = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        output.close()
        raise TailnetServeError(f"failed to start Tailscale Serve: {exc}") from exc

    session = TailnetServeSession(process, dns_name, exposed_port, target, output=output)
    deadline = time.monotonic() + TAILSCALE_READY_TIMEOUT_SECONDS
    try:
        while time.monotonic() < deadline:
            exit_code = process.poll()
            if exit_code is not None:
                detail = session.read_output()
                suffix = f": {detail}" if detail else ""
                raise TailnetServeError(f"Tailscale Serve exited with code {exit_code}{suffix}")
            status = run_tailscale_json("serve", "status", "--json")
            if tailnet_mapping_ready(status, exposed_port, target):
                return session
            time.sleep(0.25)
        raise TailnetServeError(
            f"Tailscale Serve did not publish HTTPS port {exposed_port} within {TAILSCALE_READY_TIMEOUT_SECONDS}s"
        )
    except Exception:
        session.close()
        raise


def write_tailnet_state(path: Path, state: dict) -> None:
    """Atomically persist non-secret lifecycle state for status commands."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as state_file:
            state_file.write(json.dumps(state, sort_keys=True) + "\n")
            temporary = Path(state_file.name)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_tailnet_state(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}
