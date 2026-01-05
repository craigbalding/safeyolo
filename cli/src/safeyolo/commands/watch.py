"""Watch command - monitor logs and handle approval requests."""

import json
import time
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..api import AdminAPI, APIError, get_api
from ..config import get_logs_dir

console = Console()


def tail_jsonl(path: Path, follow: bool = True):
    """Tail a JSONL file, yielding parsed events.

    Args:
        path: Path to JSONL file
        follow: If True, keep watching for new lines

    Yields:
        Parsed JSON objects from each line
    """
    if not path.exists():
        if follow:
            # Wait for file to appear
            console.print(f"[dim]Waiting for log file: {path}[/dim]")
            while not path.exists():
                time.sleep(0.5)
        else:
            return

    with open(path) as f:
        # Start from end for follow mode
        if follow:
            f.seek(0, 2)  # Seek to end

        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        pass  # Skip malformed lines
            elif follow:
                time.sleep(0.1)
            else:
                break


def format_approval_request(event: dict) -> Panel:
    """Format a credential approval request as a Rich panel."""
    data = event.get("data", {})

    # Extract key info
    rule = data.get("rule", "unknown")
    host = data.get("host", "unknown")
    fingerprint = data.get("fingerprint", "unknown")
    project_id = data.get("project_id", "default")
    reason = data.get("reason", "")
    confidence = data.get("confidence", "")
    location = data.get("location", "")
    timestamp = event.get("timestamp", "")

    # Format timestamp
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            timestamp = dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            pass  # Keep original timestamp string if parsing fails

    # Build content
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Credential", f"[bold]{rule}[/bold]")
    table.add_row("Destination", f"[cyan]{host}[/cyan]")
    table.add_row("Fingerprint", f"[dim]{fingerprint}[/dim]")
    table.add_row("Project", project_id)
    if location:
        table.add_row("Location", location)
    if confidence:
        table.add_row("Confidence", confidence)
    if reason:
        table.add_row("Reason", f"[yellow]{reason}[/yellow]")

    # Title with timestamp
    title = f"[bold red]Credential Blocked[/bold red] [dim]{timestamp}[/dim]"

    return Panel(
        table,
        title=title,
        subtitle="[green][A]pprove[/green] | [red][D]eny[/red] | [dim][S]kip[/dim]",
        border_style="red",
    )


def handle_approval(event: dict, api: AdminAPI) -> bool:
    """Handle an approval request interactively.

    Returns True if approved, False if denied/skipped.
    """
    data = event.get("data", {})
    fingerprint = data.get("fingerprint", "")
    host = data.get("host", "")
    project_id = data.get("project_id", "default")

    # Extract HMAC from fingerprint (format: "hmac:abc123...")
    if fingerprint.startswith("hmac:"):
        token_hmac = fingerprint[5:]
    else:
        token_hmac = fingerprint

    # Show the request
    console.print()
    console.print(format_approval_request(event))

    # Get user input
    while True:
        try:
            response = console.input("[bold]Action ([green]a[/green]/[red]d[/red]/[dim]s[/dim]): [/bold]").lower().strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted[/dim]")
            return False

        if response in ("a", "approve", "y", "yes"):
            # Approve
            try:
                result = api.add_approval(
                    project=project_id,
                    token_hmac=token_hmac,
                    hosts=[host],
                )
                status = result.get("status", "unknown")
                if status == "added":
                    console.print(f"[green]Approved[/green] - {token_hmac[:8]}... -> {host}")
                elif status == "exists":
                    console.print("[yellow]Already approved[/yellow]")
                else:
                    console.print(f"[green]OK[/green] - {result}")
                return True
            except APIError as e:
                console.print(f"[red]API Error:[/red] {e}")
                return False

        elif response in ("d", "deny", "n", "no"):
            console.print(f"[red]Denied[/red] - {token_hmac[:8]}...")
            return False

        elif response in ("s", "skip", ""):
            console.print("[dim]Skipped[/dim]")
            return False

        else:
            console.print("[dim]Invalid input. Use: a(pprove), d(eny), s(kip)[/dim]")


def watch(
    follow: bool = typer.Option(True, "--follow/--no-follow", "-f", help="Follow log in real-time"),
    security_only: bool = typer.Option(True, "--security/--all", help="Show only security events"),
    interactive: bool = typer.Option(True, "--interactive/--log-only", "-i", help="Prompt for approvals"),
    log_file: str | None = typer.Option(None, "--log", "-l", help="Path to log file"),
):
    """Watch logs and handle credential approval requests.

    Monitors the SafeYolo JSONL log for blocked credential requests and
    prompts you to approve or deny them interactively.

    Examples:

        safeyolo watch              # Interactive approval mode
        safeyolo watch --log-only   # Just display events, no prompts
        safeyolo watch --all        # Show all events, not just security
    """
    # Determine log path
    if log_file:
        log_path = Path(log_file)
    else:
        log_path = get_logs_dir() / "safeyolo.jsonl"

    # Get API client for approvals
    api = None
    if interactive:
        try:
            api = get_api()
            # Test connection
            api.health()
        except APIError as e:
            console.print(f"[yellow]Warning:[/yellow] Cannot connect to admin API: {e}")
            console.print("[dim]Approvals will be disabled. Run 'safeyolo start' first.[/dim]")
            api = None

    console.print(f"[bold]Watching:[/bold] {log_path}")
    if interactive and api:
        console.print("[dim]Press Ctrl+C to exit. Approval prompts will appear for blocked credentials.[/dim]")
    else:
        console.print("[dim]Press Ctrl+C to exit.[/dim]")
    console.print()

    # Track seen events to avoid duplicates
    seen_fingerprints: set[str] = set()

    try:
        for event in tail_jsonl(log_path, follow=follow):
            event_type = event.get("event", "")

            # Filter to security events if requested
            if security_only and not event_type.startswith("security."):
                continue

            # Check for credential blocks needing approval
            if event_type == "security.credential":
                data = event.get("data", {})
                decision = data.get("decision", "")
                reason = data.get("reason", "")
                fingerprint = data.get("fingerprint", "")

                # Only prompt for blocks that need approval
                if decision == "block" and reason in ("requires_approval", "destination_mismatch"):
                    # Deduplicate by fingerprint+host
                    dedup_key = f"{fingerprint}:{data.get('host', '')}"
                    if dedup_key in seen_fingerprints:
                        continue
                    seen_fingerprints.add(dedup_key)

                    if interactive and api:
                        handle_approval(event, api)
                    else:
                        # Just display the event
                        console.print(format_approval_request(event))
                else:
                    # Other security.credential events - show summary
                    _print_event_summary(event)
            else:
                # Other events - show summary
                _print_event_summary(event)

    except KeyboardInterrupt:
        console.print("\n[dim]Stopped watching.[/dim]")


def _print_event_summary(event: dict) -> None:
    """Print a one-line summary of an event."""
    event_type = event.get("event", "unknown")
    timestamp = event.get("timestamp", "")
    data = event.get("data", {})

    # Format timestamp
    if timestamp:
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            timestamp = dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp = timestamp[:19]

    # Color based on event type
    if event_type.startswith("security."):
        decision = data.get("decision", "")
        if decision == "block":
            style = "red"
        elif decision == "warn":
            style = "yellow"
        else:
            style = "cyan"
    elif event_type.startswith("admin."):
        style = "magenta"
    else:
        style = "dim"

    # Build summary
    summary_parts = []
    for key in ("decision", "rule", "host", "status", "addon"):
        if key in data:
            summary_parts.append(f"{key}={data[key]}")

    summary = " ".join(summary_parts[:4])  # Limit to 4 parts

    console.print(f"[dim]{timestamp}[/dim] [{style}]{event_type}[/{style}] {summary}")
