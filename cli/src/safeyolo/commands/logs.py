"""Log viewing and tailing commands."""

import json
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.text import Text

from ..config import find_config_dir, get_logs_dir
from ..core.audit_schema import InvalidAuditEvent, parse_audit_event, sanitize_for_log

console = Console()

# Severity colors and display
SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}

# Severity ordering for --severity filter
SEVERITY_RANK = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

# Decision colors — mirrors the Decision enum in audit_schema. SafeYolo emits
# "deny", never "block"; anything else is drift worth flagging.
DECISION_COLORS = {
    "allow": "green",
    "deny": "red bold",
    "warn": "yellow",
    "require_approval": "magenta",
    "budget_exceeded": "yellow",
    "log": "dim",
}

# How many schema-drift warnings to print per run before suppressing further
# notices. Keeps the normal human-facing log view uncluttered when an old log
# file contains many non-conforming lines.
_MAX_DRIFT_WARNINGS = 10


def format_event(event: dict) -> Text:
    """Format a log event for display using spine fields from AuditEvent contract."""
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

    # Severity
    severity = event.get("severity", "")
    sev_color = SEVERITY_COLORS.get(severity, "white")
    if severity:
        text.append(f"{severity:<8} ", style=sev_color)

    # Event type (colored by severity)
    event_type = sanitize_for_log(event.get("event", "unknown"))
    text.append(f"{event_type:<24} ", style=sev_color)

    # Decision (if present)
    decision = event.get("decision")
    if decision:
        dec_color = DECISION_COLORS.get(decision, "white")
        text.append(f"[{decision}] ", style=dec_color)

    # Summary — the human-readable description from the event
    summary = event.get("summary", "")
    if summary:
        text.append(sanitize_for_log(summary))

    # Context suffix: (agent, client_ip) when available
    agent = event.get("agent")
    details = event.get("details", {})
    client = details.get("client") or details.get("client_ip")
    context_parts = [sanitize_for_log(p) for p in (agent, client) if p]
    if context_parts:
        text.append(f"  ({', '.join(context_parts)})", style="dim")

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
        "--follow",
        "-f",
        help="Follow log output (like tail -f)",
    ),
    raw: bool = typer.Option(
        False,
        "--raw",
        help="Output raw JSONL without formatting",
    ),
    event_type: str = typer.Option(
        None,
        "--event",
        "-e",
        help="Filter by event type prefix (e.g. 'security', 'ops', 'traffic')",
    ),
    request_id: str = typer.Option(
        None,
        "--request-id",
        "-r",
        help="Filter to specific request ID",
    ),
    agent_filter: str = typer.Option(
        None,
        "--agent",
        "-a",
        help="Filter to specific agent",
    ),
    min_severity: str = typer.Option(
        None,
        "--severity",
        help="Minimum severity (low/medium/high/critical)",
    ),
    tail: int = typer.Option(
        None,
        "--tail",
        "-n",
        help="Show last N lines",
    ),
) -> None:
    """View SafeYolo logs."""

    config_dir = find_config_dir()
    if not config_dir:
        console.print("[red]No SafeYolo configuration found.[/red]\nRun [bold]safeyolo init[/bold] first.")
        raise typer.Exit(1)

    log_path = get_logs_dir() / "safeyolo.jsonl"

    if not log_path.exists():
        console.print(
            "[yellow]No logs found yet.[/yellow]\n"
            f"Log file: {log_path}\n"
            "Logs will appear after SafeYolo processes requests."
        )
        raise typer.Exit(0)

    # Validate --severity if provided
    min_sev_rank = None
    if min_severity:
        if min_severity not in SEVERITY_RANK:
            console.print(f"[red]Invalid severity: {min_severity}[/red]\nValid: low, medium, high, critical")
            raise typer.Exit(1)
        min_sev_rank = SEVERITY_RANK[min_severity]

    # If tail specified, get last N lines first
    lines_to_show = []
    if tail and not follow:
        with open(log_path) as f:
            lines_to_show = list(f)[-tail:]
    else:
        lines_to_show = None  # Will iterate file

    drift_warnings = 0

    def process_lines(line_source):
        nonlocal drift_warnings
        for line in line_source:
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if raw:
                    console.print(line)
                continue

            # Validate against the shared schema for drift detection. The
            # rendering path below is lenient (uses dict.get), so failures
            # here are warnings, not skips — an old CLI against a newer log
            # should still render events whose shape it understands.
            try:
                parse_audit_event(event)
            except InvalidAuditEvent as exc:
                if drift_warnings < _MAX_DRIFT_WARNINGS:
                    drift_warnings += 1
                    print(
                        f"[safeyolo] schema drift: {exc}",
                        file=sys.stderr,
                    )
                    if drift_warnings == _MAX_DRIFT_WARNINGS:
                        print(
                            "[safeyolo] further schema-drift warnings suppressed",
                            file=sys.stderr,
                        )

            # Apply filters
            if event_type and not event.get("event", "").startswith(event_type):
                continue
            if request_id and event.get("request_id") != request_id:
                continue
            if agent_filter and event.get("agent") != agent_filter:
                continue
            if min_sev_rank is not None:
                ev_rank = SEVERITY_RANK.get(event.get("severity", ""), -1)
                if ev_rank < min_sev_rank:
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
