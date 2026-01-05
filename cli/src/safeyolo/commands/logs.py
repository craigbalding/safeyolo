"""Log viewing and tailing commands."""

import json
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.text import Text

from ..config import find_config_dir, get_logs_dir

console = Console()

# Event type colors
EVENT_COLORS = {
    "traffic.request": "blue",
    "traffic.response": "cyan",
    "security.credential": "red",
    "security.ratelimit": "yellow",
    "security.circuit": "yellow",
    "security.pattern": "magenta",
    "admin.approve": "green",
    "admin.deny": "red",
    "admin.auth_failure": "red bold",
    "ops.startup": "green",
    "ops.config_reload": "green",
}

# Decision colors
DECISION_COLORS = {
    "allow": "green",
    "block": "red bold",
    "warn": "yellow",
    "greylist": "yellow",
}


def format_event(event: dict) -> Text:
    """Format a log event for display."""
    text = Text()

    # Timestamp
    ts = event.get("ts", "")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            ts_short = dt.strftime("%H:%M:%S")
        except (ValueError, TypeError):
            ts_short = ts[:8]
        text.append(f"{ts_short} ", style="dim")

    # Event type
    event_type = event.get("event", "unknown")
    color = EVENT_COLORS.get(event_type, "white")
    text.append(f"{event_type:<20} ", style=color)

    # Request ID
    request_id = event.get("request_id", "")
    if request_id:
        text.append(f"{request_id} ", style="dim")

    # Decision (if present)
    decision = event.get("decision")
    if decision:
        dec_color = DECISION_COLORS.get(decision, "white")
        text.append(f"[{decision}] ", style=dec_color)

    # Event-specific details
    if event_type == "traffic.request":
        method = event.get("method", "")
        host = event.get("host", "")
        path = event.get("path", "")
        text.append(f"{method} {host}{path}")

    elif event_type == "traffic.response":
        status = event.get("status", "")
        latency = event.get("latency_ms", "")
        blocked_by = event.get("blocked_by")
        text.append(f"{status}")
        if latency:
            text.append(f" ({latency}ms)", style="dim")
        if blocked_by:
            text.append(f" blocked by {blocked_by}", style="red")

    elif event_type.startswith("security."):
        host = event.get("host", "")
        reason = event.get("reason", "")
        rule = event.get("rule", event.get("credential_type", ""))
        text.append(f"{host}")
        if rule:
            text.append(f" [{rule}]", style="dim")
        if reason:
            text.append(f" - {reason}")

    elif event_type.startswith("admin."):
        details = []
        if "token_prefix" in event:
            details.append(f"token:{event['token_prefix']}...")
        if "client_ip" in event:
            details.append(f"from:{event['client_ip']}")
        if details:
            text.append(" ".join(details))

    else:
        # Generic: show all other keys
        skip_keys = {"ts", "event", "request_id", "decision"}
        extras = {k: v for k, v in event.items() if k not in skip_keys}
        if extras:
            text.append(str(extras)[:80])

    return text


def tail_file(path: Path, follow: bool = False):
    """Tail a file, optionally following for new content."""
    if not path.exists():
        console.print(f"[yellow]Log file not found: {path}[/yellow]")
        return

    if follow:
        # Use tail -f approach
        import subprocess
        process = subprocess.Popen(
            ["tail", "-f", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for line in process.stdout:
                yield line.strip()
        except KeyboardInterrupt:
            process.terminate()
    else:
        with open(path) as f:
            for line in f:
                yield line.strip()


def logs(
    follow: bool = typer.Option(
        False,
        "--follow", "-f",
        help="Follow log output (like tail -f)",
    ),
    raw: bool = typer.Option(
        False,
        "--raw",
        help="Output raw JSONL without formatting",
    ),
    security: bool = typer.Option(
        False,
        "--security", "-s",
        help="Show only security.* events",
    ),
    request_id: str = typer.Option(
        None,
        "--request-id", "-r",
        help="Filter to specific request ID",
    ),
    tail: int = typer.Option(
        None,
        "--tail", "-n",
        help="Show last N lines",
    ),
) -> None:
    """View SafeYolo logs."""

    config_dir = find_config_dir()
    if not config_dir:
        console.print(
            "[red]No SafeYolo configuration found.[/red]\n"
            "Run [bold]safeyolo init[/bold] first."
        )
        raise typer.Exit(1)

    log_path = get_logs_dir() / "safeyolo.jsonl"

    if not log_path.exists():
        console.print(
            "[yellow]No logs found yet.[/yellow]\n"
            f"Log file: {log_path}\n"
            "Logs will appear after SafeYolo processes requests."
        )
        raise typer.Exit(0)

    # If tail specified, get last N lines first
    lines_to_show = []
    if tail and not follow:
        with open(log_path) as f:
            lines_to_show = list(f)[-tail:]
    else:
        lines_to_show = None  # Will iterate file

    def process_lines(line_source):
        for line in line_source:
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if raw:
                    console.print(line)
                continue

            # Apply filters
            if security and not event.get("event", "").startswith("security."):
                continue
            if request_id and event.get("request_id") != request_id:
                continue

            # Output
            if raw:
                console.print(line)
            else:
                console.print(format_event(event))

    try:
        if lines_to_show is not None:
            process_lines(lines_to_show)
        elif follow:
            console.print("[dim]Following logs (Ctrl+C to stop)...[/dim]\n")
            process_lines(tail_file(log_path, follow=True))
        else:
            process_lines(tail_file(log_path, follow=False))
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")
