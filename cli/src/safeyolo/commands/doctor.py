"""Diagnostic command for SafeYolo - works when the proxy is broken."""

import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import typer
import yaml
from rich.console import Console

from ..config import (
    find_config_dir,
    get_admin_token_path,
    get_agent_map_path,
    get_agent_token_path,
    get_certs_dir,
    get_logs_dir,
    load_config,
)
from ..proxy import resolve_upstream_ca_cert

console = Console()

_FLOW_STORE_WARN_MB = 500


def _registered_agent_sockets() -> list[Path]:
    """Return socket paths for agents in the live-agent registry."""
    from ..sockets import path_for

    try:
        agent_map = json.loads(get_agent_map_path().read_text())
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    paths = []
    for name, entry in agent_map.items():
        try:
            paths.append(path_for(name, entry["ip"]))
        except (KeyError, TypeError, ValueError):
            continue
    return sorted(paths)


_HTTP_STATUS_RE = re.compile(
    rb"^HTTP/\d(?:\.\d)?[ \t]+([0-9]{3})(?:[ \t]+.*)?$"
)


class _HTTPResponseError(ValueError):
    """A bounded UDS response is not a complete HTTP response."""


@dataclass(frozen=True)
class _HTTPResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


def _parse_http_response(raw: bytes) -> _HTTPResponse:
    """Parse the status and headers needed by host-side UDS diagnostics."""
    if not raw:
        raise _HTTPResponseError("no response")
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise _HTTPResponseError("incomplete HTTP headers")
    lines = head.split(b"\r\n")
    match = _HTTP_STATUS_RE.fullmatch(lines[0])
    if match is None:
        raise _HTTPResponseError("malformed HTTP status line")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if not colon or not name.strip():
            raise _HTTPResponseError("malformed HTTP header")
        try:
            header_name = name.decode("ascii").strip().casefold()
            header_value = value.decode("iso-8859-1").strip()
        except UnicodeError as exc:
            raise _HTTPResponseError("malformed HTTP header") from exc
        headers[header_name] = header_value

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            expected = int(content_length)
        except ValueError as exc:
            raise _HTTPResponseError("invalid Content-Length") from exc
        if expected < 0 or len(body) < expected:
            raise _HTTPResponseError("partial HTTP body")
        body = body[:expected]

    return _HTTPResponse(
        status_code=int(match.group(1)),
        headers=headers,
        body=body,
    )


@dataclass
class DiagResult:
    """Result of a single diagnostic check."""

    name: str
    status: str  # "pass", "fail", "warn", "skip"
    message: str
    detail: str = ""
    remediation: str = ""


@dataclass
class DiagBundle:
    """Complete diagnostic bundle."""

    timestamp: str = ""
    checks: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    crash_traceback: str = ""
    system: dict = field(default_factory=dict)


def _check_config_dir() -> DiagResult:
    """Check if config directory exists."""
    config_dir = find_config_dir()
    if config_dir:
        return DiagResult(
            name="Config directory",
            status="pass",
            message=f"Found ({config_dir})",
        )
    return DiagResult(
        name="Config directory",
        status="fail",
        message="Not found (~/.safeyolo)",
        remediation="safeyolo init",
    )


def _check_proxy_process() -> DiagResult:
    """Report the verified native process and the executable that launched it."""
    from .. import rust_proxy

    process = rust_proxy.read_process()
    if process is None:
        return DiagResult("Proxy running", "fail", "Rust proxy is not running", remediation="Run: safeyolo start")
    try:
        alive = rust_proxy.is_alive(process)
        ready = rust_proxy.readiness(process) if alive else None
    except RuntimeError as exc:
        return DiagResult("Proxy running", "fail", str(exc), remediation="Inspect native launch state")
    if not alive or ready is None:
        return DiagResult("Proxy running", "fail", "Rust proxy is not ready", remediation="Run: safeyolo start")
    return DiagResult(
        "Proxy running", "pass",
        f"Rust proxy PID {process.pid} ready",
        detail=f"Executable: {process.binary_path or 'unknown'}; config: {process.config_file or 'unknown'}",
    )


def _check_firewall() -> DiagResult:
    """Verify the structural egress path is ready.

    On both platforms, agent sandboxes have no external network interface
    — the only path out is a per-agent UDS that terminates at the native proxy.
    There's no host firewall in the
    critical path, so the readiness signal is "native proxy running +
    per-agent sockets present when agents are running."
    """
    import platform as _platform
    system = _platform.system()
    if system not in ("Darwin", "Linux"):
        return DiagResult(
            name="Egress enforcement",
            status="skip",
            message=f"Unsupported platform: {system}",
        )

    from ..proxy import is_proxy_running
    from ..sockets import sockets_dir

    socks = sockets_dir()
    if is_proxy_running():
        expected = _registered_agent_sockets()
        active = [p.name for p in expected if p.exists()]
        if active:
            return DiagResult(
                name="Egress enforcement",
                status="pass",
                message=(
                    f"per-agent UDS listeners active ({len(active)} socket(s) "
                    f"in {socks})"
                ),
            )
        return DiagResult(
            name="Egress enforcement",
            status="pass",
            message=f"Rust proxy running (no agents, sockets dir {socks})",
        )
    return DiagResult(
        name="Firewall enforcement",
        status="warn",
        message=(
            f"Rust proxy not running ({socks} has no listeners). "
            "Per-agent UDS listeners are bound by the native proxy at startup."
        ),
        remediation="safeyolo start",
    )


def _check_admin_api() -> DiagResult:
    """Check if admin API is responding."""
    from .. import rust_proxy
    process = rust_proxy.read_process()
    admin_port = process.admin_port if process else None
    if admin_port is None:
        return DiagResult("Admin API", "warn", "Native operator API is not configured")
    health_url = f"http://127.0.0.1:{admin_port}/health"
    try:
        sock = socket.create_connection(("127.0.0.1", admin_port), timeout=3)
        sock.close()
    except (TimeoutError, ConnectionRefusedError, OSError):
        return DiagResult(
            name="Admin API",
            status="fail",
            message=f"Cannot connect to localhost:{admin_port}",
            remediation="Check: safeyolo logs --tail 50",
        )
    # Try a health check
    from ..config import get_admin_token

    token = get_admin_token()
    if token:
        try:
            import httpx

            resp = httpx.get(
                f"http://127.0.0.1:{admin_port}/health",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                return DiagResult(
                    name="Admin API",
                    status="pass",
                    message=f"{health_url} responding (200 OK)",
                )
            return DiagResult(
                name="Admin API",
                status="warn",
                message=f"{health_url} returned {resp.status_code}",
            )
        except Exception as exc:
            return DiagResult(
                name="Admin API",
                status="warn",
                message=f"Port open but health check failed: {type(exc).__name__}",
            )
    return DiagResult(
        name="Admin API",
        status="pass",
        message=f"127.0.0.1:{admin_port} accepting connections",
        detail="No admin token available to verify health endpoint",
    )


def _check_runtime_identity() -> DiagResult:
    """Report native process liveness and the selected executable path."""
    from .. import rust_proxy

    process = rust_proxy.read_process()
    if process is None or process.binary_path is None:
        return DiagResult("Runtime identity", "warn", "Native executable identity is unavailable")
    if not rust_proxy.is_alive(process):
        return DiagResult("Runtime identity", "fail", "Native process has exited")
    executable = Path(process.binary_path)
    if not executable.is_file():
        return DiagResult("Runtime identity", "warn", f"Selected executable moved: {executable}")
    return DiagResult("Runtime identity", "pass", f"Running {executable}", detail=f"PID {process.pid}")


def _check_pipeline_probe() -> DiagResult:
    """Self-probe the data path via a per-agent UDS.

    Connects to one of the per-agent UDS listeners and sends a request
    to the agent API virtual hostname (`_safeyolo.proxy.internal/health`).
    A 200 response proves the full host chain works:
      - UDS listener bound and accepting
      - Rust parsed the request
      - native Agent API recognized the virtual host and authenticated
      - response synthesized and returned over the same socket

    No upstream egress, no third party, no dependency on policy contents.
    Skips when no agent sockets exist (nothing to probe through).
    """
    from ..sockets import sockets_dir

    socks_dir = sockets_dir()
    if not socks_dir.exists():
        return DiagResult(
            name="Pipeline probe",
            status="skip",
            message=f"No sockets directory ({socks_dir})",
        )
    expected = _registered_agent_sockets()
    socks = [path for path in expected if path.exists()]
    if not socks:
        if expected:
            return DiagResult(
                name="Pipeline probe",
                status="fail",
                message=f"No UDS listener for registered agent ({expected[0].name})",
                remediation="safeyolo stop && safeyolo start",
            )
        return DiagResult(
            name="Pipeline probe",
            status="skip",
            message="No agent sockets present (no agents running)",
        )

    token_path = get_agent_token_path()
    try:
        token = token_path.read_text().strip()
    except FileNotFoundError:
        return DiagResult(
            name="Pipeline probe",
            status="warn",
            message=f"Agent token missing at {token_path}",
            remediation="safeyolo start (regenerates token)",
        )
    if not token:
        return DiagResult(
            name="Pipeline probe",
            status="warn",
            message="Agent token file is empty",
            remediation="safeyolo stop && safeyolo start",
        )

    sock_path = socks[0]
    request = (
        b"GET /health HTTP/1.0\r\n"
        b"Host: _safeyolo.proxy.internal\r\n"
        b"Authorization: Bearer " + token.encode() + b"\r\n"
        b"Connection: close\r\n\r\n"
    )

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(sock_path))
        s.sendall(request)
        chunks = []
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        s.close()
        response = b"".join(chunks)
    except OSError as exc:
        return DiagResult(
            name="Pipeline probe",
            status="fail",
            message=f"UDS probe failed via {sock_path.name}: {type(exc).__name__}: {exc}",
            remediation="safeyolo agent diagnostics <name> for runtime and control observations",
        )

    if not response:
        return DiagResult(
            name="Pipeline probe",
            status="fail",
            message=f"No response from {sock_path.name}",
            remediation="safeyolo logs --tail 50",
        )

    try:
        parsed_response = _parse_http_response(response)
    except _HTTPResponseError as exc:
        return DiagResult(
            name="Pipeline probe",
            status="fail",
            message=f"Malformed HTTP response via {sock_path.name}: {exc}",
            remediation="safeyolo logs --tail 50",
        )

    marker = parsed_response.headers.get("x-safeyolo-agent-api", "")
    if parsed_response.status_code != 200:
        remediation = (
            "safeyolo logs --tail 20"
            if parsed_response.status_code in {401, 403}
            and marker.casefold() == "true"
            else "safeyolo logs --tail 50"
        )
        return DiagResult(
            name="Pipeline probe",
            status="fail",
            message=f"Agent API returned HTTP {parsed_response.status_code}",
            remediation=remediation,
        )

    if marker.casefold() != "true":
        return DiagResult(
            name="Pipeline probe",
            status="fail",
            message="HTTP 200 response lacks the Agent API handler marker",
            remediation="safeyolo logs --tail 50",
        )

    body = parsed_response.body
    try:
        parsed = json.loads(body)
        pdp_status = parsed.get("pdp", "unknown")
    except (ValueError, json.JSONDecodeError):
        return DiagResult(
            name="Pipeline probe",
            status="warn",
            message=f"200 OK via {sock_path.name} but body is not JSON",
            detail=body[:200].decode(errors="replace"),
        )

    if pdp_status != "ok":
        return DiagResult(
            name="Pipeline probe",
            status="warn",
            message=f"Agent API responding via {sock_path.name}, but PDP is {pdp_status}",
            remediation="safeyolo logs --tail 50",
        )
    return DiagResult(
        name="Pipeline probe",
        status="pass",
        message=f"UDS -> native Agent API -> policy healthy ({sock_path})",
    )


def _check_ca_cert() -> DiagResult:
    """Check if CA certificate exists and is valid."""
    certs_dir = get_certs_dir()
    ca_cert = certs_dir / "mitmproxy-ca-cert.pem"
    if not ca_cert.exists():
        return DiagResult(
            name="CA certificate",
            status="warn",
            message="Not found on host (generated on first run)",
            detail=f"Expected at {ca_cert}",
        )
    try:
        cert_data = ca_cert.read_bytes()
        cert = ssl.PEM_cert_to_DER_cert(cert_data.decode())
        # Parse with ssl to check basic validity
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=cert_data.decode())
        return DiagResult(
            name="CA certificate",
            status="pass",
            message=f"Valid at {ca_cert} ({len(cert)} bytes DER)",
        )
    except Exception as exc:
        return DiagResult(
            name="CA certificate",
            status="fail",
            message=f"Invalid: {type(exc).__name__}: {exc}",
            remediation="safeyolo stop && safeyolo start (regenerates cert)",
        )


def _check_upstream_ca_cert() -> DiagResult:
    """Validate additional upstream CA trust and flag transient overrides."""
    config = load_config()
    test_config = config.get("test", {})
    if not isinstance(test_config, dict) or not test_config.get("enabled"):
        test_config = None
    proxy_config = config.get("proxy", {})
    try:
        path, source = resolve_upstream_ca_cert(test_config, proxy_config)
    except RuntimeError as exc:
        return DiagResult(
            name="Upstream CA trust",
            status="fail",
            message=str(exc),
            remediation="safeyolo proxy upstream-ca set /path/to/ca-bundle.pem",
        )
    if path is None:
        return DiagResult(
            name="Upstream CA trust",
            status="pass",
            message="Using system and certifi trust stores",
        )
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(path))
    except OSError as exc:
        return DiagResult(
            name="Upstream CA trust",
            status="fail",
            message=f"Invalid bundle from {source}: {exc}",
            detail=str(path),
            remediation="safeyolo proxy upstream-ca set /path/to/ca-bundle.pem",
        )
    if source == "SAFEYOLO_CA_CERT":
        return DiagResult(
            name="Upstream CA trust",
            status="warn",
            message="Valid environment override is not restart-persistent",
            detail=str(path),
            remediation=f"safeyolo proxy upstream-ca set {path}",
        )
    return DiagResult(
        name="Upstream CA trust",
        status="pass",
        message=f"Valid additional bundle from {source}",
        detail=str(path),
    )


def _check_baseline() -> DiagResult:
    """Check if policy file is valid (TOML or YAML)."""
    config_dir = find_config_dir()
    if not config_dir:
        return DiagResult(
            name="Baseline policy",
            status="skip",
            message="Config directory not found",
        )

    # Prefer .toml, fall back to .yaml
    baseline_path = config_dir / "policy.toml"
    if not baseline_path.exists():
        baseline_path = config_dir / "policy.yaml"
    if not baseline_path.exists():
        return DiagResult(
            name="Baseline policy",
            status="fail",
            message="Policy file not found (policy.toml or policy.yaml)",
            remediation="safeyolo init",
        )

    try:
        if baseline_path.suffix == ".toml":
            import tomlkit

            data = tomlkit.parse(baseline_path.read_text())
        else:
            with open(baseline_path) as fh:
                data = yaml.safe_load(fh)

        if not isinstance(data, dict):
            return DiagResult(
                name="Baseline policy",
                status="fail",
                message=f"Invalid {baseline_path.suffix} (not a mapping)",
                remediation="safeyolo init",
            )
        if "hosts" in data:
            # Host-centric format
            host_count = len(data.get("hosts", {}))
            return DiagResult(
                name="Baseline policy",
                status="pass",
                message=f"Valid at {baseline_path} ({host_count} hosts)",
            )
        if "permissions" not in data:
            return DiagResult(
                name="Baseline policy",
                status="warn",
                message=f"No 'permissions' or 'hosts' key in {baseline_path.name}",
            )
        perm_count = len(data.get("permissions", []))
        return DiagResult(
            name="Baseline policy",
            status="pass",
            message=f"Valid at {baseline_path} ({perm_count} permissions)",
        )
    except Exception as exc:
        return DiagResult(
            name="Baseline policy",
            status="fail",
            message=f"Parse error: {exc}",
            remediation=f"Fix syntax in {baseline_path.name} or run: safeyolo init",
        )


def _check_tokens() -> DiagResult:
    """Check admin and agent token files."""
    admin_path = get_admin_token_path()
    agent_path = get_agent_token_path()
    issues = []

    if not admin_path.exists():
        issues.append("admin_token missing")
    else:
        mode = admin_path.stat().st_mode & 0o777
        if mode & 0o077:
            issues.append(f"admin_token permissions too open ({oct(mode)})")

    if not agent_path.exists():
        # Agent token is regenerated on each proxy start — not an error
        issues.append("agent_token not yet generated (proxy not started?)")

    if not issues:
        return DiagResult(
            name="Tokens",
            status="pass",
            message=f"Token files present with correct permissions in {admin_path.parent}",
        )
    # Distinguish between real problems and first-run state
    real_issues = [i for i in issues if "not yet generated" not in i]
    if not real_issues:
        return DiagResult(
            name="Tokens",
            status="pass",
            message=f"Admin token OK at {admin_path}; agent token pending first start",
        )
    return DiagResult(
        name="Tokens",
        status="warn",
        message="; ".join(issues),
        remediation="safeyolo start (generates tokens)",
    )


def _check_vault() -> DiagResult:
    """Check service gateway vault setup."""
    from .vault import _get_key_path, _get_vault_path

    key_path = _get_key_path()
    vault_path = _get_vault_path()

    if not key_path.exists() and not vault_path.exists():
        return DiagResult(
            name="Service gateway vault",
            status="pass",
            message=f"Not configured (no {vault_path})",
        )

    if not key_path.exists():
        return DiagResult(
            name="Service gateway vault",
            status="fail",
            message="Vault key missing but vault file exists (partial setup)",
            remediation="Check ~/.safeyolo/data/ or re-run: safeyolo vault add",
        )

    if not vault_path.exists():
        return DiagResult(
            name="Service gateway vault",
            status="pass",
            message=f"Key present at {key_path}; no credentials stored at {vault_path}",
        )

    try:
        from .vault import _load_vault

        vault, _ = _load_vault()
        cred_count = len(vault.list_names())
        return DiagResult(
            name="Service gateway vault",
            status="pass",
            message=f"Unlocked {vault_path} ({cred_count} credential{'s' if cred_count != 1 else ''})",
        )
    except Exception as exc:
        return DiagResult(
            name="Service gateway vault",
            status="fail",
            message=f"Cannot decrypt: {type(exc).__name__}: {exc}",
            remediation="Check vault.key matches vault.yaml.enc",
        )


def _check_log_health() -> DiagResult:
    """Check log file sizes and disk usage."""
    logs_dir = get_logs_dir()
    if not logs_dir.exists():
        return DiagResult(
            name="Log health",
            status="pass",
            message=f"Logs directory doesn't exist yet ({logs_dir})",
        )
    try:
        usage = shutil.disk_usage(logs_dir)
        free_gb = usage.free / 1_000_000_000
        # Check JSONL size
        jsonl = logs_dir / "safeyolo.jsonl"
        jsonl_mb = jsonl.stat().st_size / 1_000_000 if jsonl.exists() else 0
        msg = f"JSONL: {jsonl_mb:.1f}MB, disk: {free_gb:.1f}GB free, dir: {logs_dir}"
        # Use absolute threshold (1GB) - percentage is misleading on large disks
        if free_gb < 1:
            return DiagResult(
                name="Log health",
                status="fail",
                message=msg,
                remediation="Free disk space or clear old logs",
            )
        if jsonl_mb > 100:
            return DiagResult(
                name="Log health",
                status="warn",
                message=msg,
                detail="JSONL file is large - consider rotation",
            )
        return DiagResult(
            name="Log health",
            status="pass",
            message=msg,
        )
    except Exception as exc:
        return DiagResult(
            name="Log health",
            status="warn",
            message=f"Could not check: {type(exc).__name__}",
        )


def _check_pending_approvals() -> DiagResult:
    """Surface blocked operator decisions without suggesting automatic approval."""
    from ..core.audit_stream import pending_approval_review

    review = pending_approval_review(get_logs_dir() / "safeyolo.jsonl")
    if review.state == "missing":
        return DiagResult(
            name="Pending approvals",
            status="skip",
            message="No audit log yet",
        )
    if review.state == "error":
        return DiagResult(
            name="Pending approvals",
            status="warn",
            message="Could not inspect the audit log for pending decisions",
        )
    if review.count == 0:
        return DiagResult(
            name="Pending approvals",
            status="pass",
            message="No unresolved decisions in the recent audit window",
        )
    return DiagResult(
        name="Pending approvals",
        status="warn",
        message=f"{review.count} unresolved operator decision(s) in the recent audit window",
        detail=(
            "; ".join(review.examples)
            + ". Review in `safeyolo watch` for this instance (same "
            "SAFEYOLO_CONFIG_DIR and SAFEYOLO_LOGS_DIR); detector classifications "
            "are provisional. "
            "Verify the agent, destination, and requested action before deciding. "
            "This warning is not an instruction to approve."
        ),
    )


def _check_flow_store() -> DiagResult:
    """Check flow store SQLite database health."""
    db_path = get_logs_dir() / "flows.sqlite3"
    if not db_path.exists():
        return DiagResult(
            name="Flow store",
            status="pass",
            message=f"Database not yet created at {db_path} (will appear on first flow)",
        )
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        count = cursor.fetchone()[0]
        conn.close()
        size_mb = db_path.stat().st_size / 1_000_000
        msg = f"OK ({count} flows, {size_mb:.1f}MB, db: {db_path})"
        if size_mb > _FLOW_STORE_WARN_MB:
            return DiagResult(
                name="Flow store",
                status="warn",
                message=msg,
                detail="Database is large — consider pruning old flows",
            )
        return DiagResult(
            name="Flow store",
            status="pass",
            message=msg,
        )
    except Exception as exc:
        return DiagResult(
            name="Flow store",
            status="warn",
            message=f"Cannot read database: {type(exc).__name__}: {exc}",
        )


def _check_vm_helper_identity() -> DiagResult:
    """Report the installed helper's source revision and local-debug authority."""
    from ..vm import VMError
    from ..vm_identity import read_vm_helper_identity

    try:
        identity = read_vm_helper_identity()
    except VMError as error:
        return DiagResult(name="VM helper", status="warn", message=str(error))
    return DiagResult(
        name="VM helper", status="warn" if identity.warning else "pass",
        message=identity.summary,
        detail=identity.warning or f"{identity.swift_compiler}; {identity.optimization}; {identity.symbols}",
    )


def _check_sandbox_runtime() -> DiagResult:
    """Check sandbox runtime availability (runsc on Linux, safeyolo-vm on macOS)."""
    import platform as _plat
    system = _plat.system()

    if system == "Darwin":
        machine = _plat.machine()
        if machine != "arm64":
            return DiagResult(
                name="Sandbox runtime",
                status="fail",
                message=f"Intel Mac ({machine}) — Virtualization.framework requires Apple Silicon (arm64)",
            )
        from ..vm import VMError, probe_vm_helper
        try:
            helper = probe_vm_helper()
        except VMError as exc:
            return DiagResult(
                name="Sandbox runtime",
                status="fail",
                message=str(exc),
                remediation="Rebuild and install the helper: make -C vm install",
            )
        return DiagResult(
            name="Sandbox runtime",
            status="pass",
            message=f"Apple Silicon, safeyolo-vm capability check passed at {helper}",
        )

    if system == "Linux":
        from ..platform.linux import find_runsc
        path = find_runsc()
        if not path:
            return DiagResult(
                name="Sandbox runtime",
                status="fail",
                message="runsc (gVisor) not found",
                remediation="Install gVisor: see README 'Linux' section",
            )
        # Get version
        version = ""
        try:
            r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3)
            version = r.stdout.strip().split("\n")[0] if r.returncode == 0 else ""
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            # Version probe is best-effort diagnostic info — report
            # the path without it if the binary is missing/hung.
            pass
        label = f"runsc at {path}"
        if version:
            label = f"{version} at {path}"
        return DiagResult(
            name="Sandbox runtime",
            status="pass",
            message=label,
        )

    return DiagResult(
        name="Sandbox runtime",
        status="fail",
        message=f"Unsupported platform: {system}",
    )


def _check_vsock_term() -> DiagResult:
    """Check macOS interactive terminal dependency."""
    import platform as _plat

    if _plat.system() != "Darwin":
        return DiagResult(
            name="Interactive terminal",
            status="skip",
            message="Not applicable (Linux uses runsc exec for terminal access)",
        )

    from ..vm import VSOCK_TERM_INSTALL_HINT, get_vsock_term_path

    path = get_vsock_term_path()
    if not path.exists():
        return DiagResult(
            name="Interactive terminal",
            status="fail",
            message=f"vsock-term missing at {path}",
            remediation=VSOCK_TERM_INSTALL_HINT,
        )
    if not path.is_file() or not os.access(path, os.X_OK):
        return DiagResult(
            name="Interactive terminal",
            status="fail",
            message=f"vsock-term is not executable at {path}",
            remediation=VSOCK_TERM_INSTALL_HINT,
        )
    return DiagResult(
        name="Interactive terminal",
        status="pass",
        message=f"vsock-term available at {path}",
    )


def _check_isolation_platform(
    sandbox_runtime: DiagResult | None = None,
) -> DiagResult:
    """Check isolation platform (KVM vs systrap vs Apple VZ)."""
    import platform as _plat
    system = _plat.system()

    if system == "Darwin":
        # A normal Doctor run passes the already-evaluated Sandbox runtime
        # result so both rows describe one immutable observation. Direct
        # callers still perform the platform and helper capability checks.
        if sandbox_runtime is not None:
            if sandbox_runtime.status != "pass":
                return DiagResult(
                    name="Isolation platform",
                    status="skip",
                    message="Skipped (depends on: Sandbox runtime)",
                )
            return DiagResult(
                name="Isolation platform",
                status="pass",
                message="Apple Virtualization.framework (hardware isolation)",
            )
        machine = _plat.machine()
        if machine != "arm64":
            return DiagResult(
                name="Isolation platform",
                status="fail",
                message=f"Apple VZ unavailable on {machine}",
            )
        from ..vm import VMError, probe_vm_helper
        try:
            probe_vm_helper()
        except VMError as exc:
            return DiagResult(
                name="Isolation platform",
                status="fail",
                message=f"Apple VZ capability check failed: {exc}",
                remediation="Rebuild and install the helper: make -C vm install",
            )
        return DiagResult(
            name="Isolation platform",
            status="pass",
            message="Apple Virtualization.framework (hardware isolation)",
        )

    if system == "Linux":
        from ..platform.linux import detect_runsc_platform
        info = detect_runsc_platform()
        if info.get("forced"):
            return DiagResult(
                name="Isolation platform",
                status="pass",
                message=(
                    "systrap (software isolation) — forced by "
                    "SAFEYOLO_RUNSC_PLATFORM"
                ),
                detail="KVM auto-detection was intentionally bypassed",
            )
        if info["platform"] == "kvm":
            return DiagResult(
                name="Isolation platform",
                status="pass",
                message="KVM (hardware isolation)",
                detail="/dev/kvm: operator rw, subordinate uid 100000 ACL set",
            )
        # systrap — report why
        if not info["kvm_exists"]:
            return DiagResult(
                name="Isolation platform",
                status="pass",
                message="systrap (software isolation) — /dev/kvm not found",
                detail="Hardware isolation (KVM) available on hosts with virtualization enabled",
            )
        if not info["kvm_operator_access"]:
            group = info.get("kvm_group") or ""
            if (
                info.get("kvm_group_has_rw")
                and group
                and not info.get("operator_in_kvm_group")
            ):
                return DiagResult(
                    name="Isolation platform",
                    status="warn",
                    message=f"systrap (software isolation) — join group '{group}' for KVM access",
                    remediation=f"sudo usermod -aG {group} $USER  (then log out and back in)",
                )
            return DiagResult(
                name="Isolation platform",
                status="warn",
                message="systrap (software isolation) — operator lacks /dev/kvm access",
                remediation="safeyolo setup",
            )
        # kvm exists, operator has access, but subordinate uid lacks ACL
        return DiagResult(
            name="Isolation platform",
            status="warn",
            message="systrap (software isolation) — subordinate uid 100000 lacks /dev/kvm ACL",
            detail="KVM available but container root can't access it",
            remediation="safeyolo setup",
        )

    return DiagResult(
        name="Isolation platform",
        status="skip",
        message=f"Unsupported platform: {system}",
    )


def _check_userns() -> DiagResult:
    """Check user namespace prerequisites (Linux only)."""
    import platform as _plat
    if _plat.system() != "Linux":
        return DiagResult(
            name="User namespaces",
            status="skip",
            message="Not applicable (macOS uses Virtualization.framework)",
        )

    from ..platform.linux import check_userns_prerequisites
    info = check_userns_prerequisites()
    issues = []

    if not info["newuidmap"]:
        issues.append("newuidmap not found")
    if not info["newgidmap"]:
        issues.append("newgidmap not found")
    if not info["subuid"]:
        issues.append("/etc/subuid: required SafeYolo range unavailable")
    if not info["subgid"]:
        issues.append("/etc/subgid: required SafeYolo range unavailable")
    if not info["setfacl"]:
        issues.append("setfacl not found (install the `acl` package)")
    if info["apparmor_restricts"] and not info["apparmor_profile_loaded"]:
        issues.append("AppArmor restricts userns but safeyolo-runsc profile not loaded")

    if not issues:
        parts = [
            "newuidmap/newgidmap available",
            "subuid/subgid configured",
            "setfacl available",
        ]
        if info["apparmor_restricts"]:
            parts.append("AppArmor profile loaded")
        return DiagResult(
            name="User namespaces",
            status="pass",
            message=", ".join(parts),
        )

    return DiagResult(
        name="User namespaces",
        status="fail",
        message="; ".join(issues),
        remediation="safeyolo setup",
    )


def _check_guest_images() -> DiagResult:
    """Check guest image availability (platform-aware)."""
    import platform as _plat

    from ..vm import check_guest_images, missing_guest_images

    if not check_guest_images():
        missing = missing_guest_images()
        remediation = "safeyolo bootstrap"
        if "rootfs-erofs" in missing:
            # Spell out the most common root cause so doctor users don't
            # rediscover it at agent-add time.
            remediation += (
                " (install erofs-utils first: "
                "sudo apt-get install erofs-utils)"
            )
        return DiagResult(
            name="Guest images",
            status="fail",
            message=f"Missing: {', '.join(missing)}",
            remediation=remediation,
        )

    if _plat.system() == "Linux":
        from ..vm import get_base_rootfs_tree_path

        tree = get_base_rootfs_tree_path()
        return DiagResult(
            name="Guest images",
            status="pass",
            message=f"rootfs tree at {tree}",
        )

    from ..config import get_share_dir

    return DiagResult(
        name="Guest images",
        status="pass",
        message=f"Available in {get_share_dir()} (Image, initramfs.cpio.gz, rootfs-base.ext4)",
    )


def _check_running_agents() -> DiagResult:
    """Read native runtime and control dimensions, including degraded agents."""
    from ..agent_lifecycle import AgentLifecycleError, list_agent_runtimes

    try:
        agents = list_agent_runtimes()
    except AgentLifecycleError as exc:
        return DiagResult(
            name="Agent runtimes", status="fail", message=str(exc),
            remediation="use the installed native CLI's status and agent diagnostics",
        )
    if not agents:
        return DiagResult(name="Agent runtimes", status="pass", message="No agents configured")
    degraded = any(agent["runtime_state"] in {"unknown", "degraded"}
                   or agent["control_state"] in {"unknown", "degraded"} for agent in agents)
    return DiagResult(
        name="Agent runtimes", status="warn" if degraded else "pass",
        message="; ".join(
            f"{agent['name']}: runtime={agent['runtime_state']}, control={agent['control_state']}, "
            f"agent={agent['agent_state']}, terminal={agent['terminal_state']}" for agent in agents
        ),
        remediation="safeyolo agent diagnostics NAME" if degraded else "",
    )


def _check_coord_message_plane() -> DiagResult:
    """Coord message plane (nats-server) health.

    Coord is best-effort infra on top of the proxy — a failure here
    means the coord API will 503, but the proxy itself is fine. This
    check surfaces the runtime state so an operator whose agents
    can't reach `/api/coord/...` knows to look at NATS rather than
    tracing through the proxy process.
    """
    from ..coord import nats_runtime as coord_nats
    try:
        info = coord_nats.status()
    except Exception as exc:  # noqa: BLE001
        return DiagResult(
            name="Coord message plane",
            status="warn",
            message=f"nats-server status query failed: {type(exc).__name__}",
        )
    state = info.get("state", "not-running")
    if state == "healthy":
        return DiagResult(
            name="Coord message plane",
            status="pass",
            message=(
                f"nats-server running (pid {info['pid']}, "
                f"listen {info['listen']}, "
                f"version {info.get('actual_version') or info['requested_version']})"
            ),
        )
    if state == "wedged":
        # Live PID we can't verify ownership of. Fail (not warn) so
        # the operator sees this in the doctor summary — silent
        # cleanup would risk orphaning a live NATS.
        return DiagResult(
            name="Coord message plane",
            status="fail",
            message=(
                f"nats-server wedged: pid {info['pid']} alive but /varz "
                f"ownership unverified"
            ),
            detail=(
                f"listen={info['listen']}  pidfile={info.get('pidfile') or 'absent'}  "
                f"log={info.get('log_file') or 'absent'}"
            ),
            remediation=(
                "Investigate the process manually. If it is not SafeYolo's "
                f"nats-server, remove the pidfile ({info.get('pidfile')}) "
                "and rerun `safeyolo start`."
            ),
        )
    if info.get("binary") is None:
        return DiagResult(
            name="Coord message plane",
            status="warn",
            message="nats-server binary not installed",
            remediation="safeyolo start — first run downloads the pinned binary",
        )
    return DiagResult(
        name="Coord message plane",
        status="warn",
        message="nats-server not running; coord API will 503",
        remediation="safeyolo stop && safeyolo start",
        detail=(
            f"listen={info['listen']}  config={info.get('config') or 'absent'}  "
            f"log={info.get('log_file') or 'absent'}"
        ),
    )


# Dependency map: check_name -> list of check_names it depends on
_DEPENDS_ON = {
    "Isolation platform": ["Sandbox runtime"],
    "User namespaces": ["Sandbox runtime"],
    "Admin API": ["Proxy running"],
    "Runtime identity": ["Admin API"],
    "Pipeline probe": ["Proxy running"],
}


def _run_checks(verbose: bool = False) -> list[DiagResult]:
    """Run all diagnostic checks with cascade logic."""
    import platform as _plat

    checks_funcs = [
        ("Config directory", _check_config_dir),
        ("Sandbox runtime", _check_sandbox_runtime),
    ]
    if _plat.system() == "Darwin":
        checks_funcs.append(("VM helper", _check_vm_helper_identity))
        checks_funcs.append(("Interactive terminal", _check_vsock_term))
    checks_funcs.extend(
        [
            ("Isolation platform", _check_isolation_platform),
        ]
    )
    if _plat.system() == "Linux":
        checks_funcs.append(("User namespaces", _check_userns))
    checks_funcs.extend(
        [
            ("Guest images", _check_guest_images),
            ("Proxy running", _check_proxy_process),
            ("Admin API", _check_admin_api),
            ("Runtime identity", _check_runtime_identity),
            ("Pipeline probe", _check_pipeline_probe),
            ("CA certificate", _check_ca_cert),
            ("Upstream CA trust", _check_upstream_ca_cert),
            ("Baseline policy", _check_baseline),
            ("Egress enforcement", _check_firewall),
            ("Coord message plane", _check_coord_message_plane),
            ("Tokens", _check_tokens),
            ("Service gateway vault", _check_vault),
            ("Log health", _check_log_health),
            ("Pending approvals", _check_pending_approvals),
            ("Flow store", _check_flow_store),
            ("Agent runtimes", _check_running_agents),
        ]
    )

    results = []
    results_by_name: dict[str, DiagResult] = {}
    unavailable_checks = set()  # checks that failed or were skipped

    for check_name, check_fn in checks_funcs:
        # Check dependencies - skip if a dependency is unavailable (failed or skipped)
        deps = _DEPENDS_ON.get(check_name, [])
        skip = False
        for dep in deps:
            if dep in unavailable_checks:
                results.append(
                    DiagResult(
                        name=check_name,
                        status="skip",
                        message=f"Skipped (depends on: {dep})",
                    )
                )
                unavailable_checks.add(check_name)
                skip = True
                break
        if skip:
            continue

        if check_name == "Isolation platform" and _plat.system() == "Darwin":
            result = _check_isolation_platform(
                sandbox_runtime=results_by_name.get("Sandbox runtime")
            )
        else:
            result = check_fn()
        results.append(result)
        results_by_name[check_name] = result
        if result.status == "fail":
            unavailable_checks.add(check_name)

    return results


def _print_results(
    results: list[DiagResult],
    verbose: bool = False,
    raw: bool = False,
) -> None:
    """Print diagnostic results to terminal using Rich.

    `raw=True` disables color + soft-wrap and forces a wide virtual width so
    that individual check lines don't get truncated / wrapped mid-token when
    grep'd on narrow terminals or piped through non-tty consumers.
    """
    if raw:
        # Fresh console with no color / no wrap; wide virtual width keeps
        # long lines intact regardless of $COLUMNS. Bypasses the module-level
        # `console` which was captured at import with the operator's terminal.
        # `color_system=None` disables *all* ANSI including bold/dim — needed
        # so FORCE_COLOR / CI environments don't reintroduce codes that break
        # downstream greppers.
        out = Console(
            color_system=None,
            force_terminal=False,
            soft_wrap=False,
            width=10_000,
            highlight=False,
        )
    else:
        out = console

    out.print("\n[bold]SafeYolo Doctor[/bold]\n")

    status_icons = {
        "pass": "[green] PASS [/green]",
        "fail": "[red] FAIL [/red]",
        "warn": "[yellow] WARN [/yellow]",
        "skip": "[dim] SKIP [/dim]",
    }

    for result in results:
        icon = status_icons.get(result.status, "[dim]  ?   [/dim]")
        out.print(f"  {icon} {result.name}: {result.message}")
        if result.detail and (verbose or result.status in ("fail", "warn")):
            for line in result.detail.split("\n")[:5]:
                out.print(f"           {line}")
        if result.remediation and result.status in ("fail", "warn"):
            out.print(f"           Fix: [bold]{result.remediation}[/bold]")

    # Summary
    counts = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1

    out.print()
    parts = []
    if counts["pass"]:
        parts.append(f"[green]{counts['pass']} pass[/green]")
    if counts["fail"]:
        parts.append(f"[red]{counts['fail']} fail[/red]")
    if counts["warn"]:
        parts.append(f"[yellow]{counts['warn']} warn[/yellow]")
    if counts["skip"]:
        parts.append(f"[dim]{counts['skip']} skip[/dim]")
    out.print(f"  Summary: {', '.join(parts)}")
    out.print()


def _build_bundle(results: list[DiagResult]) -> dict:
    """Build JSON diagnostic bundle."""
    import platform

    counts = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
    for res in results:
        counts[res.status] = counts.get(res.status, 0) + 1

    crash_tb = ""
    for res in results:
        if res.name == "Crash detection" and res.detail:
            crash_tb = res.detail

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "checks": [asdict(r) for r in results],
        "summary": counts,
        "crash_traceback": crash_tb,
        "system": {
            "platform": platform.platform(),
        },
    }


def _attempt_fix(results: list[DiagResult]) -> list[str]:
    """Attempt safe auto-remediation. Returns list of actions taken."""
    actions = []

    for result in results:
        if result.status != "fail":
            continue

        if result.name == "Proxy running":
            console.print("[bold]Auto-fix:[/bold] Starting proxy...")
            try:
                from ..proxy import start_proxy
                start_proxy()
                actions.append("Started Rust proxy")
            except Exception as exc:
                console.print(f"  [red]Failed:[/red] {exc}")

    return actions


def doctor(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit diagnostic bundle as a single JSON object on stdout (suppresses rich console).",
    ),
    raw: bool = typer.Option(
        False,
        "--raw",
        help="Human output without color / soft-wrap. Wide virtual width so lines survive grep on narrow terminals.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    fix: bool = typer.Option(False, "--fix", help="Attempt safe auto-remediation"),
) -> None:
    """Diagnose SafeYolo setup and proxy health.

    Runs a series of checks to identify issues when the proxy is broken.
    Works even when the proxy is completely down.

    Examples:

        safeyolo doctor              # Rich console output
        safeyolo doctor --json       # Single JSON object on stdout for CI / agents
        safeyolo doctor --raw        # Plain text, no color / wrap (grep-friendly)
        safeyolo doctor --fix        # Attempt auto-remediation
        safeyolo doctor -v           # Verbose output
    """
    if json_output and fix:
        # --fix is interactive-ish; mixing with --json would corrupt the JSON stream.
        raise typer.BadParameter("--fix cannot be combined with --json")

    results = _run_checks(verbose=verbose)

    if json_output:
        # Pure JSON on stdout. No rich, no timestamped file dump.
        bundle = _build_bundle(results)
        json.dump(bundle, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        _print_results(results, verbose=verbose, raw=raw)

        if fix:
            actions = _attempt_fix(results)
            if actions:
                console.print("[bold]Actions taken:[/bold]")
                for action in actions:
                    console.print(f"  - {action}")
                # Re-run checks after fix
                console.print("\n[bold]Re-checking...[/bold]")
                results = _run_checks(verbose=verbose)
                _print_results(results, verbose=verbose, raw=raw)
            else:
                console.print("[dim]No auto-fixable issues found.[/dim]")

    # Exit with error code if any checks failed. Same rule for both output modes.
    if any(r.status == "fail" for r in results):
        raise typer.Exit(1)
