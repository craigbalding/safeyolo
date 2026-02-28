"""Diagnostic command for SafeYolo - works when the proxy is broken."""

import json
import shutil
import socket
import ssl
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Optional

import typer
import yaml
from rich.console import Console

from ..config import (
    COMPOSE_NETWORK_NAME,
    find_config_dir,
    get_certs_dir,
    get_data_dir,
    get_logs_dir,
    load_config,
)
from ..docker import (
    DOCKER_INSPECT_TIMEOUT_SECONDS,
    DockerError,
    check_docker,
    get_container_name,
    get_container_status,
)

console = Console()


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
    """Check if Docker daemon is available."""
    if not check_docker():
        return DiagResult(
            name="Docker available",
            status="fail",
            message="Docker daemon not reachable",
            remediation="Start Docker Desktop or the Docker daemon",
        )
    # Get version for detail
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        version = result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        version = "unknown"
    return DiagResult(
        name="Docker available",
        status="pass",
        message=f"Docker {version}",
    )


def _check_container() -> DiagResult:
    """Check if SafeYolo container is running."""
    status = get_container_status()
    if not status:
        return DiagResult(
            name="Container running",
            status="fail",
            message="Container not found",
            remediation="safeyolo start",
        )
    container_status = status.get("status", "unknown")
    health = status.get("health", "none")
    started = status.get("started_at", "")[:19]
    if container_status == "running":
        msg = f"Running (health: {health})"
        if started:
            msg += f", started {started}"
        return DiagResult(
            name="Container running",
            status="pass",
            message=msg,
        )
    return DiagResult(
        name="Container running",
        status="fail",
        message=f"Container status: {container_status}",
        remediation="safeyolo start",
    )


def _check_mitmproxy_process() -> DiagResult:
    """Check if mitmproxy process is alive inside the container.

    Uses /proc/1/cmdline (always available) instead of pgrep (not installed
    in minimal containers). In headless mode, mitmdump runs as PID 1 via exec.
    In TUI mode, checks /proc/*/cmdline for any mitmproxy process.
    """
    name = get_container_name()
    last_error: Optional[str] = None

    # Check PID 1 cmdline (headless mode: exec mitmdump replaces shell)
    try:
        result = subprocess.run(
            ["docker", "exec", name, "cat", "/proc/1/cmdline"],
            capture_output=True,
            timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
        )
        if result.returncode == 0:
            # cmdline uses null bytes as separators
            cmdline = result.stdout.replace(b"\x00", b" ").decode(errors="replace").strip()
            if "mitmdump" in cmdline:
                return DiagResult(
                    name="mitmproxy process",
                    status="pass",
                    message="Running (PID 1)",
                )
            if "mitmproxy" in cmdline:
                return DiagResult(
                    name="mitmproxy process",
                    status="pass",
                    message="Running in TUI mode (PID 1)",
                )
    except subprocess.TimeoutExpired as exc:
        last_error = f"Timeout while checking mitmproxy process via docker exec: {exc}"
    except FileNotFoundError as exc:
        last_error = f"docker executable not found while checking mitmproxy process: {exc}"
            name="mitmproxy process",
            status="fail",
            message=f"Unable to inspect container process: {type(exc).__name__}",
            remediation="Ensure Docker is installed, the Docker daemon is running, and the SafeYolo container is accessible.",
        )

    # TUI mode: mitmproxy runs under tmux, not as PID 1.
    # Scan /proc/*/cmdline for any mitmproxy/mitmdump process.
    try:
        # Shell glob /proc/[0-9]*/cmdline and grep - works without pgrep/ps
        result = subprocess.run(
            [
                "docker",
                "exec",
                name,
                "sh",
                "-c",
                (
                    "for f in /proc/[0-9]*/cmdline; do "
                    + "cat \"$f\" 2>/dev/null | tr '\\0' ' '; echo \" $f\"; "
                    + "done | grep -E 'mitmdump|mitmproxy' | head -1"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
        )
        if result.returncode == 0 and result.stdout.strip():
            line = result.stdout.strip()
    except subprocess.TimeoutExpired as exc:
        last_error = f"Timeout while scanning mitmproxy processes via docker exec: {exc}"
    except FileNotFoundError as exc:
        last_error = f"docker executable not found while scanning mitmproxy processes: {exc}"
            if "/proc/" in line:
    detail = "The proxy process may have crashed."
    if last_error:
        detail = f"{detail} Last error: {last_error}"

                parts = line.rsplit("/proc/", 1)[-1]
                pid = parts.split("/")[0]
            mode = "TUI mode" if "mitmproxy" in line and "mitmdump" not in line else "headless"
            return DiagResult(
        detail=detail,
                status="pass",
                message=f"Running in {mode} (PID {pid})",
            )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return DiagResult(
        name="mitmproxy process",
        status="fail",
        message="mitmproxy not running inside container",
        detail="The proxy process may have crashed.",
        remediation="safeyolo stop && safeyolo start",
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
    """Check if baseline.yaml is valid."""
    config_dir = find_config_dir()
    if not config_dir:
        return DiagResult(
            name="Baseline policy",
            status="skip",
            message="Config directory not found",
        )
    baseline_path = config_dir / "baseline.yaml"
    if not baseline_path.exists():
        return DiagResult(
            name="Baseline policy",
            status="fail",
            message="baseline.yaml not found",
            remediation="safeyolo init",
        )
    try:
        with open(baseline_path) as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict):
            return DiagResult(
                name="Baseline policy",
                status="fail",
                message="Invalid YAML (not a mapping)",
                remediation="safeyolo init",
            )
        if "permissions" not in data:
            return DiagResult(
                name="Baseline policy",
                status="warn",
                message="No 'permissions' key in baseline.yaml",
            )
        perm_count = len(data.get("permissions", []))
        return DiagResult(
            name="Baseline policy",
            status="pass",
            message=f"Valid ({perm_count} permissions)",
        )
    except yaml.YAMLError as exc:
        return DiagResult(
            name="Baseline policy",
            status="fail",
            message=f"YAML parse error: {exc}",
            remediation="Fix syntax in baseline.yaml or run: safeyolo init",
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


def _check_docker_network() -> DiagResult:
    """Check if the SafeYolo Docker network exists."""
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", COMPOSE_NETWORK_NAME],
            capture_output=True,
            text=True,
            timeout=DOCKER_INSPECT_TIMEOUT_SECONDS,
        )
        if result.returncode == 0:
            return DiagResult(
                name="Docker network",
                status="pass",
                message=f"Network '{COMPOSE_NETWORK_NAME}' exists",
            )
        return DiagResult(
            name="Docker network",
            status="fail",
            message=f"Network '{COMPOSE_NETWORK_NAME}' not found",
            remediation="safeyolo stop && safeyolo start",
        )
    except Exception as exc:
        return DiagResult(
            name="Docker network",
            status="warn",
            message=f"Could not inspect: {type(exc).__name__}",
        )


# Dependency map: check_name -> list of check_names it depends on
_DEPENDS_ON = {
    "mitmproxy process": ["Container running"],
    "Admin API": ["mitmproxy process"],
    "Proxy port": ["mitmproxy process"],
    "Docker network": ["Docker available"],
}


def _run_checks(verbose: bool = False) -> list[DiagResult]:
    """Run all diagnostic checks with cascade logic."""
    checks_funcs = [
        ("Config directory", _check_config_dir),
        ("Docker available", _check_docker),
        ("Container running", _check_container),
        ("mitmproxy process", _check_mitmproxy_process),
        ("Admin API", _check_admin_api),
        ("Proxy port", _check_proxy_port),
        ("CA certificate", _check_ca_cert),
        ("Baseline policy", _check_baseline),
        ("Crash detection", _check_crash_logs),
        ("Log health", _check_log_health),
        ("Docker network", _check_docker_network),
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
        pass

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

        if result.name == "Container running":
            console.print("[bold]Auto-fix:[/bold] Starting SafeYolo...")
            try:
                from ..docker import start

                start()
                actions.append("Started SafeYolo container")
            except DockerError as exc:
                console.print(f"  [red]Failed:[/red] {exc}")

        elif result.name == "mitmproxy process":
            console.print("[bold]Auto-fix:[/bold] Restarting SafeYolo...")
            try:
                from ..docker import restart

                restart()
                actions.append("Restarted SafeYolo container")
            except DockerError as exc:
                console.print(f"  [red]Failed:[/red] {exc}")

        elif result.name == "Docker network":
            console.print("[bold]Auto-fix:[/bold] Recreating network via restart...")
            try:
                from ..docker import start, stop

                stop()
                start()
                actions.append("Recreated SafeYolo (stop + start)")
            except DockerError as exc:
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
