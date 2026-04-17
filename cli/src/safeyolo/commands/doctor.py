"""Diagnostic command for SafeYolo - works when the proxy is broken."""

import json
import shutil
import socket
import sqlite3
import ssl
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

import typer
import yaml
from rich.console import Console

from ..config import (
    find_config_dir,
    get_admin_token_path,
    get_agent_token_path,
    get_certs_dir,
    get_data_dir,
    get_logs_dir,
    load_config,
)
from ..proxy import is_proxy_running

console = Console()

_FLOW_STORE_WARN_MB = 500


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


def _check_docker() -> DiagResult:
    """Check if proxy is running (replaces Docker check)."""
    if not is_proxy_running():
        return DiagResult(
            name="Proxy running",
            status="fail",
            message="mitmproxy is not running",
            remediation="Run: safeyolo start",
        )
    return DiagResult(name="Proxy running", status="pass", message="mitmproxy is running")


def _check_firewall() -> DiagResult:
    """Verify the structural egress path is ready.

    On both platforms, agent sandboxes have no external network interface
    — the only path out is a per-agent UDS that terminates at mitmproxy
    via the proxy_bridge. There's no host firewall in the critical path,
    so the readiness signal is "bridge daemon alive + per-agent sockets
    present when agents are running."
    """
    import platform as _platform
    system = _platform.system()
    if system not in ("Darwin", "Linux"):
        return DiagResult(
            name="Egress enforcement",
            status="skip",
            message=f"Unsupported platform: {system}",
        )

    from ..proxy_bridge import is_bridge_running, sockets_dir

    socks = sockets_dir()
    if is_bridge_running():
        active = [p.name for p in socks.glob("*.sock")] if socks.exists() else []
        if active:
            return DiagResult(
                name="Egress enforcement",
                status="pass",
                message=f"proxy UDS bridge active ({len(active)} agent socket(s) in {socks})",
            )
        return DiagResult(
            name="Egress enforcement",
            status="pass",
            message=f"proxy UDS bridge active (no agents running, sockets dir {socks})",
        )
    return DiagResult(
        name="Firewall enforcement",
        status="warn",
        message=(
            f"proxy UDS bridge not running ({socks} not being served). "
            f"The bridge starts automatically when the proxy starts."
        ),
        remediation="safeyolo start",
    )


def _check_admin_api() -> DiagResult:
    """Check if admin API is responding."""
    config = load_config()
    admin_port = config.get("proxy", {}).get("admin_port", 9090)
    try:
        sock = socket.create_connection(("127.0.0.1", admin_port), timeout=3)
        sock.close()
    except (TimeoutError, ConnectionRefusedError, OSError):
        return DiagResult(
            name="Admin API",
            status="fail",
            message=f"Cannot connect to localhost:{admin_port}",
            remediation="Check: docker logs safeyolo",
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
                    message="Responding (200 OK)",
                )
            return DiagResult(
                name="Admin API",
                status="warn",
                message=f"Responding but returned {resp.status_code}",
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
        message=f"Port {admin_port} accepting connections",
        detail="No admin token available to verify health endpoint",
    )


def _check_proxy_port() -> DiagResult:
    """Check if proxy port is accepting connections."""
    config = load_config()
    proxy_port = config.get("proxy", {}).get("port", 8080)
    try:
        sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=3)
        sock.close()
        return DiagResult(
            name="Proxy port",
            status="pass",
            message=f"Port {proxy_port} accepting connections",
        )
    except (TimeoutError, ConnectionRefusedError, OSError):
        return DiagResult(
            name="Proxy port",
            status="fail",
            message=f"Cannot connect to localhost:{proxy_port}",
            remediation="Check: docker logs safeyolo",
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
            message=f"Valid ({len(cert)} bytes DER)",
        )
    except Exception as exc:
        return DiagResult(
            name="CA certificate",
            status="fail",
            message=f"Invalid: {type(exc).__name__}: {exc}",
            remediation="safeyolo stop && safeyolo start (regenerates cert)",
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
                message=f"Valid ({host_count} hosts) [{baseline_path.name}]",
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
            message=f"Valid ({perm_count} permissions) [{baseline_path.name}]",
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
            message="Token files present with correct permissions",
        )
    # Distinguish between real problems and first-run state
    real_issues = [i for i in issues if "not yet generated" not in i]
    if not real_issues:
        return DiagResult(
            name="Tokens",
            status="pass",
            message="Admin token OK; agent token pending first start",
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
            message="Not configured (gateway disabled)",
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
            message="Key present, no credentials stored yet",
        )

    try:
        from .vault import _load_vault

        vault, _ = _load_vault()
        cred_count = len(vault.list_names())
        return DiagResult(
            name="Service gateway vault",
            status="pass",
            message=f"Unlocked ({cred_count} credential{'s' if cred_count != 1 else ''})",
        )
    except Exception as exc:
        return DiagResult(
            name="Service gateway vault",
            status="fail",
            message=f"Cannot decrypt: {type(exc).__name__}: {exc}",
            remediation="Check vault.key matches vault.yaml.enc",
        )


def _check_crash_logs() -> DiagResult:
    """Scan mitmproxy logs for crash tracebacks."""
    logs_dir = get_logs_dir()
    log_file = logs_dir / "mitmproxy.log"
    if not log_file.exists():
        return DiagResult(
            name="Crash detection",
            status="pass",
            message="No mitmproxy.log file (first run?)",
        )
    try:
        # Read last 200 lines
        lines = log_file.read_text().splitlines()[-200:]
        tracebacks = []
        in_traceback = False
        current_tb = []
        for line in lines:
            if "Traceback" in line:
                in_traceback = True
                current_tb = [line]
            elif in_traceback:
                current_tb.append(line)
                if line and not line.startswith(" ") and not line.startswith("\t"):
                    tracebacks.append("\n".join(current_tb))
                    in_traceback = False
                    current_tb = []
        if in_traceback and current_tb:
            tracebacks.append("\n".join(current_tb))
        if tracebacks:
            latest = tracebacks[-1]
            return DiagResult(
                name="Crash detection",
                status="warn",
                message=f"Found {len(tracebacks)} traceback(s) in mitmproxy.log",
                detail=latest[-500:],
                remediation="safeyolo stop && safeyolo start",
            )
        return DiagResult(
            name="Crash detection",
            status="pass",
            message="No tracebacks in recent logs",
        )
    except Exception as exc:
        return DiagResult(
            name="Crash detection",
            status="warn",
            message=f"Could not read log: {type(exc).__name__}",
        )


def _check_log_health() -> DiagResult:
    """Check log file sizes and disk usage."""
    logs_dir = get_logs_dir()
    if not logs_dir.exists():
        return DiagResult(
            name="Log health",
            status="pass",
            message="Logs directory doesn't exist yet",
        )
    try:
        usage = shutil.disk_usage(logs_dir)
        free_gb = usage.free / 1_000_000_000
        # Check JSONL size
        jsonl = logs_dir / "safeyolo.jsonl"
        jsonl_mb = jsonl.stat().st_size / 1_000_000 if jsonl.exists() else 0
        msg = f"JSONL: {jsonl_mb:.1f}MB, disk: {free_gb:.1f}GB free"
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


def _check_flow_store() -> DiagResult:
    """Check flow store SQLite database health."""
    db_path = get_logs_dir() / "flows.sqlite3"
    if not db_path.exists():
        return DiagResult(
            name="Flow store",
            status="pass",
            message="Database not yet created (will appear on first flow)",
        )
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM flows")
        count = cursor.fetchone()[0]
        conn.close()
        size_mb = db_path.stat().st_size / 1_000_000
        msg = f"OK ({count} flows, {size_mb:.1f}MB)"
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


def _check_addon_loading() -> DiagResult:
    """Check if addons are loaded and reporting via /stats."""
    config = load_config()
    admin_port = config.get("proxy", {}).get("admin_port", 9090)

    from ..config import get_admin_token

    token = get_admin_token()
    if not token:
        return DiagResult(
            name="Addon loading",
            status="warn",
            message="No admin token — cannot verify addons",
        )
    try:
        import httpx

        resp = httpx.get(
            f"http://127.0.0.1:{admin_port}/stats",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5.0,
        )
        if resp.status_code != 200:
            return DiagResult(
                name="Addon loading",
                status="warn",
                message=f"/stats returned {resp.status_code}",
            )
        stats = resp.json()
        addon_names = [k for k in stats if k != "proxy"]
        return DiagResult(
            name="Addon loading",
            status="pass",
            message=f"{len(addon_names)} addons reporting",
            detail=", ".join(sorted(addon_names)),
        )
    except Exception as exc:
        return DiagResult(
            name="Addon loading",
            status="warn",
            message=f"Stats check failed: {type(exc).__name__}",
        )



# Dependency map: check_name -> list of check_names it depends on
_DEPENDS_ON = {
    "Admin API": ["Proxy running"],
    "Addon loading": ["Admin API"],
    "Proxy port": ["Proxy running"],
}


def _run_checks(verbose: bool = False) -> list[DiagResult]:
    """Run all diagnostic checks with cascade logic."""
    checks_funcs = [
        ("Config directory", _check_config_dir),
        ("Proxy running", _check_docker),  # Reused — now checks proxy, not Docker
        ("Admin API", _check_admin_api),
        ("Addon loading", _check_addon_loading),
        ("Proxy port", _check_proxy_port),
        ("CA certificate", _check_ca_cert),
        ("Baseline policy", _check_baseline),
        ("Egress enforcement", _check_firewall),
        ("Tokens", _check_tokens),
        ("Service gateway vault", _check_vault),
        ("Crash detection", _check_crash_logs),
        ("Log health", _check_log_health),
        ("Flow store", _check_flow_store),
    ]

    results = []
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

        result = check_fn()
        results.append(result)
        if result.status == "fail":
            unavailable_checks.add(check_name)

    return results


def _print_results(results: list[DiagResult], verbose: bool = False) -> None:
    """Print diagnostic results to terminal using Rich."""
    console.print("\n[bold]SafeYolo Doctor[/bold]\n")

    status_icons = {
        "pass": "[green] PASS [/green]",
        "fail": "[red] FAIL [/red]",
        "warn": "[yellow] WARN [/yellow]",
        "skip": "[dim] SKIP [/dim]",
    }

    for result in results:
        icon = status_icons.get(result.status, "[dim]  ?   [/dim]")
        console.print(f"  {icon} {result.name}: {result.message}")
        if result.detail and (verbose or result.status in ("fail", "warn")):
            for line in result.detail.split("\n")[:5]:
                console.print(f"           {line}")
        if result.remediation and result.status in ("fail", "warn"):
            console.print(f"           Fix: [bold]{result.remediation}[/bold]")

    # Summary
    counts = {"pass": 0, "fail": 0, "warn": 0, "skip": 0}
    for result in results:
        counts[result.status] = counts.get(result.status, 0) + 1

    console.print()
    parts = []
    if counts["pass"]:
        parts.append(f"[green]{counts['pass']} pass[/green]")
    if counts["fail"]:
        parts.append(f"[red]{counts['fail']} fail[/red]")
    if counts["warn"]:
        parts.append(f"[yellow]{counts['warn']} warn[/yellow]")
    if counts["skip"]:
        parts.append(f"[dim]{counts['skip']} skip[/dim]")
    console.print(f"  Summary: {', '.join(parts)}")
    console.print()


def _build_bundle(results: list[DiagResult]) -> dict:
    """Build JSON diagnostic bundle."""
    # Get docker version
    docker_version = "unknown"
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            docker_version = result.stdout.strip()
    except Exception:
        pass  # docker may not be installed or accessible; fall back to "unknown"

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
            "docker_version": docker_version,
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
                actions.append("Started mitmproxy")
            except Exception as exc:
                console.print(f"  [red]Failed:[/red] {exc}")

    return actions


def doctor(
    json_output: bool = typer.Option(False, "--json", help="Write JSON diagnostic bundle"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    fix: bool = typer.Option(False, "--fix", help="Attempt safe auto-remediation"),
) -> None:
    """Diagnose SafeYolo setup and proxy health.

    Runs a series of checks to identify issues when the proxy is broken.
    Works even when the proxy is completely down.

    Examples:

        safeyolo doctor              # Run diagnostics
        safeyolo doctor --json       # Write JSON bundle for agents
        safeyolo doctor --fix        # Attempt auto-remediation
        safeyolo doctor -v           # Verbose output
    """
    results = _run_checks(verbose=verbose)

    _print_results(results, verbose=verbose)

    if fix:
        actions = _attempt_fix(results)
        if actions:
            console.print("[bold]Actions taken:[/bold]")
            for action in actions:
                console.print(f"  - {action}")
            # Re-run checks after fix
            console.print("\n[bold]Re-checking...[/bold]")
            results = _run_checks(verbose=verbose)
            _print_results(results, verbose=verbose)
        else:
            console.print("[dim]No auto-fixable issues found.[/dim]")

    if json_output:
        bundle = _build_bundle(results)
        # Write to ~/.safeyolo/
        data_dir = get_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        bundle_path = data_dir / f"doctor_{ts}.json"
        with open(bundle_path, "w") as fh:
            json.dump(bundle, fh, indent=2)
        console.print(f"[dim]Bundle written to {bundle_path}[/dim]")

    # Exit with error code if any checks failed
    if any(r.status == "fail" for r in results):
        raise typer.Exit(1)
