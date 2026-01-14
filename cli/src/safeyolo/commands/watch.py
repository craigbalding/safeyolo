"""Watch command - monitor logs and handle approval requests."""

import json
import os
import shutil
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..api import AdminAPI, APIError, get_api
from ..config import get_logs_dir

console = Console()

# Default status file location
STATUS_FILE = Path.home() / ".cache" / "safeyolo" / "tmux_status.txt"


def is_in_tmux() -> bool:
    """Check if we're running inside a tmux session."""
    return bool(os.environ.get("TMUX"))


def has_tmux() -> bool:
    """Check if tmux command is available."""
    return shutil.which("tmux") is not None


def tmux_toast(message: str) -> bool:
    """Send a toast notification via tmux display-message.

    Returns True if successful, False otherwise.
    """
    if not has_tmux():
        return False

    try:
        subprocess.run(
            ["tmux", "display-message", message],
            capture_output=True,
            check=True,
            timeout=2,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


@dataclass
class RollingStats:
    """Track rolling window statistics for status line."""

    window_seconds: int = 300  # 5 minute window
    _events: deque = field(default_factory=deque)
    total_requests: int = 0
    total_blocks: int = 0
    total_warnings: int = 0
    pending_approvals: int = 0
    _pending_fingerprints: set = field(default_factory=set)

    def add_event(self, event: dict) -> None:
        """Record an event and update stats."""
        now = time.time()
        event_type = event.get("event", "")

        # Track all security events
        if event_type.startswith("security."):
            self._events.append((now, event))
            self.total_requests += 1

            decision = event.get("decision", "")
            if decision == "block":
                self.total_blocks += 1
                # Track pending approvals by fingerprint
                reason = event.get("reason", "")
                if reason in ("requires_approval", "destination_mismatch"):
                    fingerprint = event.get("fingerprint", "")
                    if fingerprint and fingerprint not in self._pending_fingerprints:
                        self._pending_fingerprints.add(fingerprint)
                        self.pending_approvals += 1
            elif decision == "warn":
                self.total_warnings += 1

        # Prune old events
        self._prune(now)

    def mark_resolved(self, fingerprint: str) -> None:
        """Mark a pending approval as resolved."""
        if fingerprint in self._pending_fingerprints:
            self._pending_fingerprints.discard(fingerprint)
            self.pending_approvals = max(0, self.pending_approvals - 1)

    def _prune(self, now: float) -> None:
        """Remove events outside the rolling window."""
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def window_counts(self) -> tuple[int, int, int]:
        """Get counts within the rolling window."""
        now = time.time()
        self._prune(now)

        requests = 0
        blocks = 0
        warnings = 0
        for _, event in self._events:
            if event.get("event", "").startswith("security."):
                requests += 1
                decision = event.get("decision", "")
                if decision == "block":
                    blocks += 1
                elif decision == "warn":
                    warnings += 1

        return requests, blocks, warnings

    def format_status_line(self) -> str:
        """Format a compact status line for tmux."""
        win_req, win_block, win_warn = self.window_counts()

        # Determine status indicator
        if self.pending_approvals > 0:
            indicator = "!"  # Needs attention
        elif win_block > 0:
            indicator = "x"  # Recent blocks
        elif win_warn > 0:
            indicator = "~"  # Warnings only
        else:
            indicator = "+"  # All clear

        parts = [f"SY {indicator}", f"{win_req}req"]

        if win_block > 0:
            parts.append(f"{win_block}blk")
        if win_warn > 0:
            parts.append(f"{win_warn}wrn")
        if self.pending_approvals > 0:
            parts.append(f"{self.pending_approvals}pend")

        return " ".join(parts)


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
    # Fields are at root level, not nested under "data"
    rule = event.get("rule", "unknown")
    host = event.get("host", "unknown")
    fingerprint = event.get("fingerprint", "unknown")
    client_ip = event.get("client_ip", "")
    reason = event.get("reason", "")
    confidence = event.get("confidence", "")
    location = event.get("location", "")
    ts = event.get("ts", "")

    # Format timestamp
    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]  # Fallback to truncated string

    # Build content
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Credential", f"[bold]{rule}[/bold]")
    table.add_row("Destination", f"[cyan]{host}[/cyan]")
    table.add_row("Fingerprint", f"[dim]{fingerprint}[/dim]")
    if client_ip:
        table.add_row("Client", client_ip)
    if location:
        table.add_row("Location", location)
    if confidence:
        table.add_row("Confidence", confidence)
    if reason:
        table.add_row("Reason", f"[yellow]{reason}[/yellow]")

    # Title with timestamp
    title = f"[bold red]Credential Blocked[/bold red] [dim]{timestamp_str}[/dim]"

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
    # Fields are at root level, not nested under "data"
    fingerprint = event.get("fingerprint", "")
    host = event.get("host", "")

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
            # Approve - use "baseline" as the policy target
            try:
                result = api.add_approval(
                    project="baseline",
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


def write_status_file(stats: RollingStats, path: Path = STATUS_FILE) -> None:
    """Write status line to file for tmux to read."""
    path.parent.mkdir(parents=True, exist_ok=True)
    status_line = stats.format_status_line()
    # Atomic write via temp file
    tmp = path.with_suffix(".tmp")
    tmp.write_text(status_line + "\n")
    tmp.rename(path)


def watch_tmux(log_path: Path, interval: int, toasts: bool = True) -> None:
    """Run in tmux mode - emit status lines periodically.

    Args:
        log_path: Path to JSONL log file
        interval: Seconds between status updates
        toasts: Send tmux toasts for events needing attention
    """
    stats = RollingStats()
    last_status_time = 0.0  # Force immediate first write
    toasted_fingerprints: set[str] = set()  # Avoid repeat toasts

    # Check tmux availability for toasts
    tmux_available = has_tmux() and (is_in_tmux() or True)  # Works even outside tmux
    if toasts and not tmux_available:
        console.print("[yellow]Warning:[/yellow] tmux not available, toasts disabled")
        toasts = False

    console.print(f"[bold]Tmux mode:[/bold] Writing status to {STATUS_FILE}")
    console.print(f"[dim]Interval: {interval}s | Toasts: {'on' if toasts else 'off'} | Ctrl+C to exit[/dim]")
    console.print()

    # Wait for log file
    if not log_path.exists():
        console.print(f"[dim]Waiting for log file: {log_path}[/dim]")
        while not log_path.exists():
            time.sleep(0.5)
            # Still write status while waiting
            now = time.time()
            if now - last_status_time >= interval:
                write_status_file(stats)
                last_status_time = now

    try:
        with open(log_path) as f:
            f.seek(0, 2)  # Start from end

            while True:
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            stats.add_event(event)

                            # Send toast for events needing approval
                            if toasts:
                                _maybe_toast(event, toasted_fingerprints)

                        except json.JSONDecodeError:
                            pass  # Skip malformed log lines

                # Write status at interval (regardless of events)
                now = time.time()
                if now - last_status_time >= interval:
                    write_status_file(stats)
                    console.print(f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim] {stats.format_status_line()}")
                    last_status_time = now

                # Short sleep to avoid busy loop, but responsive to new events
                if not line:
                    time.sleep(0.1)

    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")
        # Write final "stopped" status
        STATUS_FILE.write_text("SY - stopped\n")


def _maybe_toast(event: dict, toasted: set[str]) -> None:
    """Send a tmux toast if this event needs attention."""
    event_type = event.get("event", "")

    # Only toast for credential blocks needing approval
    if event_type != "security.credential_guard":
        return

    decision = event.get("decision", "")
    reason = event.get("reason", "")

    if decision != "block" or reason not in ("requires_approval", "destination_mismatch"):
        return

    # Deduplicate by fingerprint+host
    fingerprint = event.get("fingerprint", "")
    host = event.get("host", "unknown")
    dedup_key = f"{fingerprint}:{host}"

    if dedup_key in toasted:
        return
    toasted.add(dedup_key)

    # Build toast message
    rule = event.get("rule", "credential")
    message = f"SafeYolo: {rule} blocked for {host} (approval needed)"

    if tmux_toast(message):
        console.print(f"[dim]Toast sent:[/dim] {message}")


def watch(
    follow: bool = typer.Option(True, "--follow/--no-follow", "-f", help="Follow log in real-time"),
    security_only: bool = typer.Option(True, "--security/--all", help="Show only security events"),
    interactive: bool = typer.Option(True, "--interactive/--log-only", "-i", help="Prompt for approvals"),
    log_file: str | None = typer.Option(None, "--log", "-l", help="Path to log file"),
    tmux: bool = typer.Option(False, "--tmux", "-t", help="Tmux status mode - write status file"),
    interval: int = typer.Option(2, "--interval", "-n", help="Status update interval in seconds (tmux mode)"),
    toasts: bool = typer.Option(True, "--toasts/--no-toasts", help="Send tmux toasts for approval events (tmux mode)"),
):
    """Watch logs and handle credential approval requests.

    Monitors the SafeYolo JSONL log for blocked credential requests and
    prompts you to approve or deny them interactively.

    Examples:

        safeyolo watch              # Interactive approval mode
        safeyolo watch --log-only   # Just display events, no prompts
        safeyolo watch --all        # Show all events, not just security
        safeyolo watch --tmux       # Tmux status mode with toasts
        safeyolo watch --tmux -n 5  # Tmux mode with 5s interval
        safeyolo watch --tmux --no-toasts  # Tmux mode without toasts
    """
    # Determine log path
    if log_file:
        log_path = Path(log_file)
    else:
        log_path = get_logs_dir() / "safeyolo.jsonl"

    # Tmux mode - separate code path
    if tmux:
        watch_tmux(log_path, interval, toasts=toasts)
        return

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
            # Fields are at root level, not nested under "data"
            if event_type == "security.credential_guard":
                decision = event.get("decision", "")
                reason = event.get("reason", "")
                fingerprint = event.get("fingerprint", "")

                # Only prompt for blocks that need approval
                if decision == "block" and reason in ("requires_approval", "destination_mismatch"):
                    # Deduplicate by fingerprint+host
                    dedup_key = f"{fingerprint}:{event.get('host', '')}"
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
    ts = event.get("ts", "")

    # Format timestamp
    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]

    # Color based on event type - fields are at root level
    if event_type.startswith("security."):
        decision = event.get("decision", "")
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

    # Build summary - fields are at root level
    summary_parts = []
    for key in ("decision", "rule", "host", "reason", "status", "addon"):
        if key in event:
            summary_parts.append(f"{key}={event[key]}")

    summary = " ".join(summary_parts[:4])  # Limit to 4 parts

    console.print(f"[dim]{timestamp_str}[/dim] [{style}]{event_type}[/{style}] {summary}")
