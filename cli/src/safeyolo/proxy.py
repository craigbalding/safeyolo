"""Host-side lifecycle and configuration helpers for the native proxy."""

from __future__ import annotations

import logging
import os
import time
from pathlib import Path

from . import rust_proxy
from .config import get_config_dir, get_data_dir, load_config
from .ignore_hosts import normalize_ignore_hosts
from .tailnet import TAILSCALE_OPERATION_TIMEOUT_SECONDS

log = logging.getLogger("safeyolo.proxy")


def web_tailnet_status_file() -> Path:
    return get_data_dir() / "web-tailnet-status.json"


def prior_python_proxy_running() -> bool:
    """Recognize a prior package's live process without taking ownership of it."""
    marker = get_data_dir() / "proxy.pid"
    try:
        pid = int(marker.read_text().strip())
    except FileNotFoundError:
        return False
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Cannot inspect prior Python proxy marker: {marker}") from exc
    if pid <= 1:
        raise RuntimeError(f"Invalid prior Python proxy marker: {marker}")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        marker.unlink(missing_ok=True)
        return False
    except PermissionError:
        return True
    return True


def selected_backend(config: dict | None = None) -> str:
    """Validate legacy configuration while requiring the native release path."""
    selected = load_config() if config is None else config
    options = selected.get("proxy", {})
    if not isinstance(options, dict):
        raise ValueError("proxy configuration must be a mapping")
    backend = options.get("backend", "rust")
    if backend != "rust":
        raise ValueError(
            "proxy.backend: python is unavailable in this release; "
            "use the pinned prior package for explicit rollback"
        )
    return "rust"


def check_running_backend() -> bool:
    """Reject starting a second proxy when the prior package still owns ingress."""
    selected_backend()
    if is_proxy_running():
        return True
    if prior_python_proxy_running():
        raise RuntimeError(
            "A prior Python proxy is still running; stop it with the pinned prior package before starting Rust"
        )
    return False


def start_proxy() -> None:
    """Start only the installed native executable; a failed start has no fallback."""
    with rust_proxy.lifecycle_lock():
        config = load_config()
        selected_backend(config)
        if check_running_backend():
            log.info("Native proxy already running")
            return
        stale = rust_proxy.read_process()
        if stale is not None:
            rust_proxy.clear_process(stale)
        rust_proxy.start(config)


def stop_proxy() -> None:
    with rust_proxy.lifecycle_lock():
        process = rust_proxy.read_process()
        if process is not None:
            rust_proxy.stop(process)
        elif prior_python_proxy_running():
            raise RuntimeError(
                "A prior Python proxy is running; stop it with the pinned prior package"
            )


def is_proxy_running() -> bool:
    process = rust_proxy.read_process()
    return process is not None and rust_proxy.is_alive(process)


def sync_proxy_modes(admin_port: int = 9090, timeout: float = 5.0) -> bool:
    """Reconcile the current agent map with native Unix listeners."""
    del admin_port
    try:
        return rust_proxy.sync_listeners(timeout=timeout) if is_proxy_running() else False
    except (OSError, ValueError, RuntimeError) as exc:
        log.warning("Cannot synchronize native listeners: %s", exc)
        return False


def sync_proxy_ignore_hosts(
    hosts: list[str] | None = None,
    admin_port: int | None = None,
    timeout: float = 5.0,
) -> bool:
    """Push configured exact passthrough hosts to the native operator API."""
    import httpx

    config = load_config()
    if hosts is None:
        hosts = normalize_ignore_hosts(config.get("proxy", {}).get("ignore_hosts", []))
    else:
        hosts = normalize_ignore_hosts(hosts)
    process = rust_proxy.read_process()
    if process is not None:
        admin_port = process.admin_port
    if admin_port is None:
        return False
    token_path = get_data_dir() / "admin_token"
    if not token_path.exists():
        log.warning("admin_token not found; skipping proxy ignore-host sync")
        return False
    try:
        response = httpx.put(
            f"http://127.0.0.1:{admin_port}/admin/proxy/ignore-hosts",
            json={"hosts": hosts},
            headers={"Authorization": f"Bearer {token_path.read_text().strip()}"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        log.warning("proxy ignore-host sync failed: %s: %s", type(exc).__name__, exc)
        return False
    if response.status_code != 200:
        log.warning("proxy ignore-host sync returned %d: %s", response.status_code, response.text[:200])
        return False
    return True


def sync_web_tailnet(
    enabled: bool,
    port: int,
    *,
    admin_port: int | None = None,
    timeout: float = TAILSCALE_OPERATION_TIMEOUT_SECONDS + 2.0,
) -> tuple[bool, dict]:
    """Request WebMITM sharing where the selected native operator API supports it."""
    import httpx

    process = rust_proxy.read_process()
    if process is not None:
        admin_port = process.admin_port
    token_path = get_data_dir() / "admin_token"
    if admin_port is None or not token_path.exists():
        return False, {"error": "native operator API is unavailable"}
    try:
        response = httpx.put(
            f"http://127.0.0.1:{admin_port}/admin/proxy/web-tailnet",
            json={"enabled": enabled, "port": port},
            headers={"Authorization": f"Bearer {token_path.read_text().strip()}"},
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        return False, {"error": f"{type(exc).__name__}: {exc}"}
    try:
        payload = response.json()
    except ValueError:
        payload = {"error": response.text[:200] or "invalid admin API response"}
    if not isinstance(payload, dict):
        payload = {"error": "unexpected admin API response"}
    return response.status_code == 200, payload


def wait_for_healthy(timeout: int = 30, admin_port: int = 9090) -> bool:
    """Require native process readiness and its authenticated operator health."""
    import urllib.error
    import urllib.request

    process = rust_proxy.read_process()
    if process is None:
        return False
    if process.admin_port is None:
        return rust_proxy.is_alive(process) and rust_proxy.readiness(process) is not None
    admin_port = process.admin_port
    token_path = Path(process.admin_token_file) if process.admin_token_file else None
    token = token_path.read_text().strip() if token_path and token_path.exists() else ""
    for _ in range(timeout):
        if not rust_proxy.is_alive(process) or rust_proxy.readiness(process) is None:
            return False
        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{admin_port}/health",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                if response.status == 200:
                    return rust_proxy.is_alive(process) and rust_proxy.readiness(process) is not None
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(1)
    return False


def resolve_upstream_ca_cert(
    test_config: dict | None,
    proxy_config: dict | None,
) -> tuple[Path | None, str | None]:
    candidates = (
        ("test.ca_cert", (test_config or {}).get("ca_cert")),
        ("SAFEYOLO_CA_CERT", os.environ.get("SAFEYOLO_CA_CERT")),
        ("proxy.upstream_ca_cert", (proxy_config or {}).get("upstream_ca_cert")),
    )
    for source, value in candidates:
        if value in (None, ""):
            continue
        if not isinstance(value, str):
            raise RuntimeError(f"{source} must be a filesystem path")
        path = Path(value).expanduser()
        if not path.is_file():
            raise RuntimeError(f"CA cert not found: {path}")
        return path, source
    return None, None


def get_ca_cert_path() -> Path | None:
    cert = get_config_dir() / "certs" / "mitmproxy-ca-cert.pem"
    return cert if cert.exists() else None
