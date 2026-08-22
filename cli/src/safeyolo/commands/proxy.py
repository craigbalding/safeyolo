"""Operator-only proxy configuration commands."""

from __future__ import annotations

import os
import ssl
import webbrowser
from copy import deepcopy
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from ..config import load_config, save_config
from ..events import EventKind, Severity, write_event
from ..ignore_hosts import normalize_ignore_host, normalize_ignore_hosts
from ..proxy import (
    is_proxy_running,
    sync_proxy_ignore_hosts,
    sync_web_tailnet,
    web_tailnet_status_file,
)
from ..tailnet import (
    TailnetServeError,
    preflight_tailnet_serve,
    read_tailnet_state,
    run_tailscale_json,
    tailnet_identity,
    tailnet_mapping_ready,
    tailnet_port_in_use,
    tailnet_url,
    validate_tailnet_port,
)

console = Console()

proxy_app = typer.Typer(
    name="proxy",
    help="Manage host-side proxy configuration.",
    no_args_is_help=True,
)
ignore_host_app = typer.Typer(
    name="ignore-host",
    help="Manage exact TLS passthrough hosts.",
    no_args_is_help=True,
)
web_app = typer.Typer(
    name="web",
    help="Manage the operator WebMITM interface.",
    no_args_is_help=True,
)
upstream_ca_app = typer.Typer(
    name="upstream-ca",
    help="Manage additional CA trust for upstream TLS verification.",
    no_args_is_help=True,
)
proxy_app.add_typer(ignore_host_app, name="ignore-host")
proxy_app.add_typer(web_app, name="web")
proxy_app.add_typer(upstream_ca_app, name="upstream-ca")


def _validate_upstream_ca_file(path: Path) -> None:
    """Reject missing, malformed, or key-bearing upstream CA bundles."""
    if not path.is_file():
        raise ValueError(f"CA bundle not found: {path}")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read CA bundle: {exc}") from exc
    if b"PRIVATE KEY" in content:
        raise ValueError("CA bundle must not contain a private key")
    if b"-----BEGIN CERTIFICATE-----" not in content:
        raise ValueError("CA bundle contains no PEM certificates")
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(path))
    except OSError as exc:
        raise ValueError(f"invalid CA bundle: {exc}") from exc


def _upstream_ca_restart_note() -> None:
    if is_proxy_running():
        console.print(
            "[yellow]Restart SafeYolo to apply this upstream trust change.[/yellow]"
        )
    else:
        console.print("[dim]Applies on next SafeYolo start.[/dim]")


@upstream_ca_app.command("set")
def upstream_ca_set(
    bundle: Path = typer.Argument(..., help="PEM certificate or CA bundle path"),
) -> None:
    """Persist an additional CA bundle for verified upstream TLS."""
    path = bundle.expanduser().resolve()
    try:
        _validate_upstream_ca_file(path)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    config = load_config()
    config.setdefault("proxy", {})["upstream_ca_cert"] = str(path)
    save_config(config)
    console.print(f"[green]Configured upstream CA bundle:[/green] {escape(str(path))}")
    _upstream_ca_restart_note()


@upstream_ca_app.command("remove")
def upstream_ca_remove() -> None:
    """Remove the persistent additional upstream CA bundle."""
    config = load_config()
    proxy_config = config.setdefault("proxy", {})
    if not proxy_config.get("upstream_ca_cert"):
        console.print("[yellow]No persistent upstream CA bundle is configured.[/yellow]")
        return
    proxy_config["upstream_ca_cert"] = ""
    save_config(config)
    console.print("[green]Removed persistent upstream CA bundle.[/green]")
    _upstream_ca_restart_note()


@upstream_ca_app.command("show")
def upstream_ca_show() -> None:
    """Show persistent and environment-provided upstream CA trust."""
    configured = load_config().get("proxy", {}).get("upstream_ca_cert", "")
    environment = os.environ.get("SAFEYOLO_CA_CERT", "")
    console.print(
        f"Persistent upstream CA: {escape(str(configured))}"
        if configured
        else "Persistent upstream CA: [dim]not configured[/dim]"
    )
    if environment:
        console.print(
            f"Environment override: {escape(environment)} "
            "[yellow](not persistent)[/yellow]"
        )


def _web_tailnet_config(config: dict) -> dict:
    proxy_config = config.setdefault("proxy", {})
    value = proxy_config.setdefault("web_tailnet", {"enabled": False, "port": 443})
    if not isinstance(value, dict):
        raise ValueError("proxy.web_tailnet must be a mapping")
    return value


def _web_target(config: dict) -> str:
    return f"http://127.0.0.1:{int(config['proxy'].get('web_port', 8081))}"


def _web_tailnet_runtime(config: dict) -> dict:
    """Inspect configured and actual state without mutating Tailscale."""
    share = _web_tailnet_config(config)
    enabled = share.get("enabled", False) is True
    port = share.get("port", 443)
    result = {
        "enabled": enabled,
        "port": port,
        "state": "disabled" if not enabled else "inactive",
        "url": None,
        "detail": None,
    }
    if not enabled:
        return result
    try:
        validate_tailnet_port(port)
        dns_name = tailnet_identity()
        result["url"] = tailnet_url(dns_name, port)
        serve_status = run_tailscale_json("serve", "status", "--json")
        target = _web_target(config)
        if tailnet_mapping_ready(serve_status, port, target):
            result["state"] = "healthy"
        elif tailnet_port_in_use(serve_status, port):
            result["state"] = "collision"
            result["detail"] = "port is mapped to a different target"
        elif is_proxy_running():
            state = read_tailnet_state(web_tailnet_status_file())
            result["state"] = "degraded"
            result["detail"] = state.get("detail") or "Serve mapping is absent"
    except (TailnetServeError, ValueError) as exc:
        result["state"] = "degraded" if is_proxy_running() else "inactive"
        result["detail"] = str(exc)
    return result


def _apply_web_config(config: dict, previous: dict) -> bool:
    """Persist and live-reconcile a web change, rolling back both on failure."""
    running = is_proxy_running()
    save_config(config)
    if not running:
        return False

    share = _web_tailnet_config(config)
    admin_port = int(config["proxy"].get("admin_port", 9090))
    applied, result = sync_web_tailnet(
        share.get("enabled") is True,
        int(share.get("port", 443)),
        admin_port=admin_port,
    )
    if applied:
        return True

    save_config(previous)
    prior_share = _web_tailnet_config(previous)
    restored, restore_result = sync_web_tailnet(
        prior_share.get("enabled") is True,
        int(prior_share.get("port", 443)),
        admin_port=int(previous["proxy"].get("admin_port", 9090)),
    )
    error = str(result.get("error") or "live reconcile failed")
    if not restored:
        restore_error = str(restore_result.get("error") or "live rollback failed")
        raise RuntimeError(
            f"change failed ({error}); previous live state could not be restored "
            f"({restore_error})"
        )
    raise RuntimeError(f"change failed; previous configuration and live state restored: {error}")


def _print_web_share(runtime: dict) -> None:
    url = runtime.get("url")
    if url:
        console.print(f"WebMITM Tailnet URL: [bold cyan]{escape(str(url))}[/bold cyan]")
    console.print(
        "[dim]Authentication remains enabled; use the host's existing SafeYolo admin credential when prompted.[/dim]"
    )


@web_app.command("share")
def web_share(  # DOC: README.md
    tailnet: bool = typer.Option(
        False,
        "--tailnet",
        help="Persistently publish WebMITM with Tailscale Serve",
    ),
    port: int | None = typer.Option(
        None,
        "--port",
        min=1,
        max=65535,
        help="Tailnet HTTPS port (default: 443)",
    ),
) -> None:
    """Persistently share WebMITM with authenticated Tailnet HTTPS."""
    if not tailnet:
        console.print("[red]Error:[/red] choose the sharing boundary with --tailnet")
        raise typer.Exit(2)

    config = load_config()
    previous = deepcopy(config)
    proxy_config = config.setdefault("proxy", {})
    if proxy_config.get("web_host", "127.0.0.1") != "127.0.0.1":
        console.print("[red]Error:[/red] Tailnet sharing requires proxy.web_host to remain 127.0.0.1")
        raise typer.Exit(2)
    share = _web_tailnet_config(config)
    selected_port = port if port is not None else int(share.get("port", 443))
    try:
        validate_tailnet_port(selected_port)
        target = _web_target(config)
        same_config = (
            is_proxy_running() and share.get("enabled") is True and share.get("port", 443) == selected_port
        )
        current_runtime = _web_tailnet_runtime(config) if same_config else {}
        already_active = current_runtime.get("state") == "healthy"
        dns_name = preflight_tailnet_serve(
            selected_port,
            allow_target=target if already_active else None,
        )
    except (TailnetServeError, ValueError) as exc:
        event = (
            "ops.web_tailnet_share_collision"
            if "already has a Tailscale Serve mapping" in str(exc)
            else "ops.web_tailnet_share_enable_failed"
        )
        write_event(
            event,
            kind=EventKind.OPS,
            severity=Severity.HIGH,
            summary="WebMITM Tailnet sharing preflight failed",
            addon="cli.proxy.web",
            details={"port": selected_port, "error": str(exc)},
        )
        console.print(f"[red]WebMITM share preflight failed:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from exc

    if already_active:
        console.print("[yellow]WebMITM Tailnet sharing is already active.[/yellow]")
        _print_web_share({"url": tailnet_url(dns_name, selected_port), "state": "healthy"})
        return

    share["enabled"] = True
    share["port"] = selected_port
    try:
        applied = _apply_web_config(config, previous)
    except RuntimeError as exc:
        write_event(
            "ops.web_tailnet_share_enable_failed",
            kind=EventKind.OPS,
            severity=Severity.HIGH,
            summary="Failed to enable persistent WebMITM Tailnet sharing",
            addon="cli.proxy.web",
            details={"port": selected_port, "error": str(exc)},
        )
        console.print(f"[red]Failed to enable WebMITM sharing:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from exc

    write_event(
        "ops.web_tailnet_share_enabled",
        kind=EventKind.OPS,
        severity=Severity.HIGH,
        summary=f"Persistent WebMITM Tailnet sharing enabled on port {selected_port}",
        addon="cli.proxy.web",
        details={"port": selected_port},
    )
    suffix = "applied to running proxy" if applied else "applies on next SafeYolo start"
    console.print(f"[green]WebMITM Tailnet sharing enabled[/green] [dim]({suffix})[/dim]")
    runtime = _web_tailnet_runtime(config)
    if runtime.get("url") is None:
        runtime["url"] = tailnet_url(dns_name, selected_port)
    _print_web_share(runtime)


@web_app.command("unshare")
def web_unshare() -> None:
    """Disable persistent WebMITM Tailnet sharing."""
    config = load_config()
    previous = deepcopy(config)
    share = _web_tailnet_config(config)
    if share.get("enabled") is not True:
        console.print("[yellow]WebMITM Tailnet sharing is already disabled.[/yellow]")
        return
    old_port = int(share.get("port", 443))
    share["enabled"] = False
    try:
        applied = _apply_web_config(config, previous)
    except RuntimeError as exc:
        write_event(
            "ops.web_tailnet_share_disable_failed",
            kind=EventKind.OPS,
            severity=Severity.HIGH,
            summary="Failed to disable persistent WebMITM Tailnet sharing",
            addon="cli.proxy.web",
            details={"port": old_port, "error": str(exc)},
        )
        console.print(f"[red]Failed to disable WebMITM sharing:[/red] {escape(str(exc))}")
        raise typer.Exit(1) from exc
    write_event(
        "ops.web_tailnet_share_disabled",
        kind=EventKind.OPS,
        severity=Severity.HIGH,
        summary=f"Persistent WebMITM Tailnet sharing disabled on port {old_port}",
        addon="cli.proxy.web",
        details={"port": old_port},
    )
    suffix = "applied to running proxy" if applied else "applies on next SafeYolo start"
    console.print(f"[green]WebMITM Tailnet sharing disabled[/green] [dim]({suffix})[/dim]")


@web_app.command("status")
def web_status() -> None:
    """Show local and Tailnet WebMITM access state."""
    config = load_config()
    runtime = _web_tailnet_runtime(config)
    proxy_config = config["proxy"]
    table = Table(title="WebMITM Interface", show_header=False)
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row(
        "Local",
        f"http://127.0.0.1:{int(proxy_config.get('web_port', 8081))}",
    )
    table.add_row("Proxy", "[green]running[/green]" if is_proxy_running() else "stopped")
    table.add_row("Tailnet", "enabled" if runtime["enabled"] else "disabled")
    if runtime["enabled"]:
        state = str(runtime["state"])
        style = "green" if state == "healthy" else "yellow"
        table.add_row("Tailnet Health", f"[{style}]{escape(state)}[/{style}]")
        table.add_row("Tailnet HTTPS Port", str(runtime["port"]))
        if runtime.get("url"):
            table.add_row("Tailnet URL", escape(str(runtime["url"])))
        if runtime.get("detail"):
            table.add_row("Detail", escape(str(runtime["detail"])))
    console.print(table)


@web_app.command("open")
def web_open() -> None:
    """Open the configured WebMITM interface in the operator's browser."""
    if not is_proxy_running():
        console.print("[red]WebMITM is not running.[/red] Start SafeYolo first.")
        raise typer.Exit(1)
    config = load_config()
    runtime = _web_tailnet_runtime(config)
    if runtime["enabled"]:
        if runtime["state"] != "healthy" or not runtime.get("url"):
            console.print(
                f"[red]Tailnet WebMITM share is {escape(str(runtime['state']))}.[/red] "
                "Run [bold]safeyolo proxy web status[/bold] for details."
            )
            raise typer.Exit(1)
        url = str(runtime["url"])
    else:
        url = f"http://127.0.0.1:{int(config['proxy'].get('web_port', 8081))}"
    console.print(f"Opening: {escape(url)}")
    webbrowser.open(url)


def _load_entries() -> tuple[dict, list[str]]:
    config = load_config()
    proxy_config = config.setdefault("proxy", {})
    entries = normalize_ignore_hosts(proxy_config.get("ignore_hosts", []))
    proxy_config["ignore_hosts"] = entries
    return config, entries


def _save_and_sync(config: dict, entries: list[str]) -> bool:
    config["proxy"]["ignore_hosts"] = entries
    save_config(config)
    if not is_proxy_running():
        return False
    admin_port = int(config["proxy"].get("admin_port", 9090))
    if not sync_proxy_ignore_hosts(entries, admin_port=admin_port):
        console.print(
            "[red]Saved, but the running proxy could not be updated.[/red] "
            "Restart SafeYolo to apply the persisted configuration."
        )
        raise typer.Exit(1)
    return True


@ignore_host_app.command("add")
def ignore_host_add(
    host: str = typer.Argument(..., help="Exact HOST or HOST:PORT to pass through"),
) -> None:
    """Add an exact host to the TLS passthrough list."""
    try:
        normalized = normalize_ignore_host(host)
        config, entries = _load_entries()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    if normalized in entries:
        console.print(f"[yellow]Already configured:[/yellow] {escape(normalized)}")
        return

    entries.append(normalized)
    applied = _save_and_sync(config, entries)
    suffix = "applied to running proxy" if applied else "applies on next start"
    console.print(f"[green]Added TLS passthrough:[/green] {escape(normalized)} [dim]({suffix})[/dim]")


@ignore_host_app.command("remove")
def ignore_host_remove(
    host: str = typer.Argument(..., help="Exact HOST or HOST:PORT to remove"),
) -> None:
    """Remove an exact host from the TLS passthrough list."""
    try:
        normalized = normalize_ignore_host(host)
        config, entries = _load_entries()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    if normalized not in entries:
        console.print(f"[yellow]Not found:[/yellow] {escape(normalized)}")
        raise typer.Exit(1)

    entries.remove(normalized)
    applied = _save_and_sync(config, entries)
    suffix = "applied to running proxy" if applied else "applies on next start"
    console.print(f"[green]Removed TLS passthrough:[/green] {escape(normalized)} [dim]({suffix})[/dim]")


@ignore_host_app.command("list")
def ignore_host_list() -> None:
    """List exact operator-managed TLS passthrough hosts."""
    try:
        _, entries = _load_entries()
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(2) from exc

    if not entries:
        console.print("[dim]No operator-managed TLS passthrough hosts.[/dim]")
        return

    table = Table(title="TLS Passthrough Hosts")
    table.add_column("Host", style="cyan")
    for entry in entries:
        table.add_row(entry)
    console.print(table)
