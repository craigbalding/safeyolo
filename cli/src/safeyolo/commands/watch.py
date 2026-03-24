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

from .._tactics import TACTIC_LABELS
from ..api import AdminAPI, APIError, get_api
from ..config import get_logs_dir

console = Console()

# Default status file location
STATUS_FILE = Path.home() / ".cache" / "safeyolo" / "tmux_status.txt"

# Interactive mode: how often to print status summaries
STATUS_INTERVAL = 10  # seconds between status lines
STATUS_BATCH = 10  # or after this many suppressed allow events


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
        kind = event.get("kind", "")

        # Track security and gateway events
        if kind in ("security", "gateway"):
            self._events.append((now, event))
            self.total_requests += 1

            decision = event.get("decision", "")
            if decision in ("deny", "require_approval", "budget_exceeded"):
                self.total_blocks += 1
                # Track pending approvals via approval field
                approval = event.get("approval", {})
                if approval and approval.get("required"):
                    dedup_key = f"{approval.get('key', '')}:{approval.get('target', '')}"
                    if dedup_key and dedup_key not in self._pending_fingerprints:
                        self._pending_fingerprints.add(dedup_key)
                        self.pending_approvals += 1
            elif decision == "warn":
                self.total_warnings += 1

        # Prune old events
        self._prune(now)

    def mark_resolved(self, dedup_key: str) -> None:
        """Mark a pending approval as resolved."""
        if dedup_key in self._pending_fingerprints:
            self._pending_fingerprints.discard(dedup_key)
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
            kind = event.get("kind", "")
            if kind in ("security", "gateway"):
                requests += 1
                decision = event.get("decision", "")
                if decision in ("deny", "require_approval", "budget_exceeded"):
                    blocks += 1
                elif decision == "warn":
                    warnings += 1

        return requests, blocks, warnings

    def window_allows_by_host(self) -> dict[str, int]:
        """Get allow counts per host in the rolling window."""
        now = time.time()
        self._prune(now)
        counts: dict[str, int] = {}
        for _, event in self._events:
            kind = event.get("kind", "")
            if kind in ("security", "gateway") and event.get("decision") == "allow":
                host = event.get("host", "unknown")
                counts[host] = counts.get(host, 0) + 1
        return counts

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

    Handles log rotation and proxy restarts: if the file is replaced
    (inode changes) or truncated, reopens from the beginning of the
    new file.

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

    check_interval = 0  # counter for periodic stale-file checks

    with open(path) as f:
        original_inode = os.fstat(f.fileno()).st_ino

        # Start from end for follow mode
        if follow:
            f.seek(0, 2)  # Seek to end

        while True:
            line = f.readline()
            if line:
                check_interval = 0
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue  # Skip malformed lines
            elif follow:
                time.sleep(0.1)
                check_interval += 1

                # Every ~2 seconds of no data, check if the file was rotated
                if check_interval >= 20:
                    check_interval = 0
                    try:
                        if path.exists():
                            current_inode = path.stat().st_ino
                            if current_inode != original_inode:
                                # File was rotated — reopen from start of new file
                                console.print("[dim]Log rotated, reopening...[/dim]")
                                f.close()
                                # Re-enter with new file via recursive yield
                                yield from _tail_reopened(path)
                                return
                        else:
                            # File disappeared (proxy stopped) — wait for it
                            console.print("[dim]Log file removed, waiting...[/dim]")
                            while not path.exists():
                                time.sleep(0.5)
                            console.print("[dim]Log file reappeared, reopening...[/dim]")
                            f.close()
                            yield from _tail_reopened(path)
                            return
                    except OSError:
                        continue  # stat failed, try again next cycle
            else:
                break


def _tail_reopened(path: Path):
    """Reopen a rotated/recreated log file and tail from the beginning."""
    with open(path) as f:
        original_inode = os.fstat(f.fileno()).st_ino
        check_interval = 0

        while True:
            line = f.readline()
            if line:
                check_interval = 0
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue  # Skip malformed log lines
            else:
                time.sleep(0.1)
                check_interval += 1
                if check_interval >= 20:
                    check_interval = 0
                    try:
                        if path.exists():
                            current_inode = path.stat().st_ino
                            if current_inode != original_inode:
                                console.print("[dim]Log rotated again, reopening...[/dim]")
                                f.close()
                                yield from _tail_reopened(path)
                                return
                        else:
                            while not path.exists():
                                time.sleep(0.5)
                            console.print("[dim]Log file reappeared, reopening...[/dim]")
                            f.close()
                            yield from _tail_reopened(path)
                            return
                    except OSError:
                        continue  # Transient stat error, retry next cycle


def _risky_route_dedup_key(event: dict) -> str:
    """Build dedup key for a risky route event: agent:service:method:path."""
    details = event.get("details", {})
    agent = event.get("agent", "")
    service = details.get("service", "")
    method = details.get("method", "")
    path = details.get("path", details.get("risky_route", ""))
    return f"gw:{agent}:{service}:{method}:{path}"


def scan_pending_approvals(log_path: Path) -> list[dict]:
    """Scan log backwards for unresolved approval requests since the operator last acted.

    Reads the log from the end. Collects risky route blocks and credential
    approval requests. Stops when it hits an operator action (grant added,
    approval added, denial logged) — everything before that was already
    handled. Returns unresolved events from after that point.
    """
    if not log_path.exists():
        return []

    # Operator action events — hitting one means the operator was engaged
    OPERATOR_ACTIONS = {
        "admin.gateway_grant",
        "admin.gateway_grant_revoked",
        "admin.approval_added",
        "admin.denial",
    }

    # Read lines from file (we need to scan backwards, so read all then reverse)
    # Bounded: only keep last 50K lines to avoid reading huge files
    MAX_SCAN_LINES = 50_000
    recent_lines: deque[str] = deque(maxlen=MAX_SCAN_LINES)
    try:
        with open(log_path) as f:
            for line in f:
                recent_lines.append(line)
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Failed to scan log for pending approvals: {e}")
        return []

    # Scan backwards: collect blocks, stop at first operator action
    risky_blocks: dict[str, dict] = {}  # dedup_key -> event
    credential_blocks: dict[str, dict] = {}  # dedup_key -> event

    for line in reversed(recent_lines):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        event_type = event.get("event", "")

        # Stop at the most recent operator action — everything before was handled
        if event_type in OPERATOR_ACTIONS:
            break

        decision = event.get("decision", "")

        # Collect risky route blocks
        if event_type == "gateway.risky_route" and decision == "require_approval":
            key = _risky_route_dedup_key(event)
            if key not in risky_blocks:  # keep most recent (first seen in reverse)
                risky_blocks[key] = event

        # Collect credential approval requests
        approval = event.get("approval", {})
        if approval and approval.get("required"):
            cred_key = f"{approval.get('key', '')}:{approval.get('target', '')}"
            if cred_key not in credential_blocks:
                credential_blocks[cred_key] = event

    # Return all collected (they're unresolved — no operator action after them)
    pending = list(risky_blocks.values()) + list(credential_blocks.values())

    # Sort by timestamp (oldest first) so prompts appear in chronological order
    pending.sort(key=lambda e: e.get("ts", ""))

    return pending


def format_approval_request(event: dict) -> Panel:
    """Format a credential approval request as a Rich panel."""
    # Use spine fields from audit event envelope
    approval = event.get("approval", {})
    details = event.get("details", {})
    host = event.get("host", "unknown")
    rule = details.get("rule", approval.get("approval_type", "unknown"))
    fingerprint = approval.get("key", details.get("fingerprint", "unknown"))
    client_ip = details.get("client_ip", "")
    reason = details.get("reason", "")
    confidence = details.get("confidence", "")
    location = details.get("location", "")
    ts = event.get("ts", "")

    # Format timestamp
    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.astimezone().strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]  # Fallback to truncated string

    # Build content
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Credential", f"[bold]{rule}[/bold]")
    table.add_row("Destination", f"[cyan]{host}[/cyan]")
    table.add_row("Credential ID", f"[dim]{fingerprint}[/dim] [dim italic](same ID = same key)[/dim]")
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
        subtitle="[green][A]pprove[/green] | [red][D]eny[/red] | [dim][L]ater[/dim]",
        border_style="red",
    )


def format_risky_route_approval(event: dict) -> Panel:
    """Format a risky route approval request as a Rich panel."""
    details = event.get("details", {})
    ts = event.get("ts", "")

    service = details.get("service", "unknown")
    capability = details.get("capability", "")
    method = details.get("method", "")
    path = details.get("path", "")
    risky_route_pattern = details.get("risky_route", "")
    tactics = details.get("tactics", [])
    enables = details.get("enables", [])
    irreversible = details.get("irreversible", False)
    description = details.get("description", "")
    agent = event.get("agent", "unknown")

    # Format timestamp
    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.astimezone().strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]

    # Build content table
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Agent", f"[bold]{agent}[/bold]")
    table.add_row("Service", f"[cyan]{service}[/cyan]")
    if capability:
        table.add_row("Capability", capability)
    display_path = path or risky_route_pattern
    table.add_row("Route", f"[bold]{method} {display_path}[/bold]")
    if description:
        table.add_row("Description", description)
    if tactics:
        labeled = ", ".join(f"{t} ({TACTIC_LABELS.get(t, t)})" for t in tactics)
        table.add_row("Tactics", labeled)
    if enables:
        labeled = ", ".join(f"{e} ({TACTIC_LABELS.get(e, e)})" for e in enables)
        table.add_row("Enables", labeled)
    if irreversible:
        table.add_row("Irreversible", "[bold red]Yes — cannot be undone[/bold red]")

    # Title with timestamp
    border_style = "red" if irreversible else "yellow"
    title = f"[bold {border_style}]Risky Route Blocked[/bold {border_style}] [dim]{timestamp_str}[/dim]"

    if irreversible:
        subtitle = "[yellow]Type yes to approve[/yellow] | [red][D]eny[/red] | [dim][L]ater[/dim]"
    else:
        subtitle = "[green][A]pprove once[/green] | [red][D]eny[/red] | [dim][L]ater[/dim]"

    return Panel(
        table,
        title=title,
        subtitle=subtitle,
        border_style=border_style,
    )


def handle_risky_route_approval(event: dict, api: AdminAPI) -> bool:
    """Handle a risky route approval request interactively.

    Returns True if approved, False if denied/skipped.
    """
    details = event.get("details", {})
    agent = event.get("agent", "unknown")
    service = details.get("service", "unknown")
    method = details.get("method", "")
    path = details.get("path", details.get("risky_route", ""))
    irreversible = details.get("irreversible", False)

    # Show the request
    console.print()
    console.print(format_risky_route_approval(event))

    # Get user input
    while True:
        try:
            if irreversible:
                response = console.input(
                    "[bold]Type yes to approve, [red]d[/red] to deny, [dim]l[/dim]ater: [/bold]"
                ).strip()
            else:
                response = (
                    console.input("[bold]Action ([green]a[/green]/[red]d[/red]/[dim]l[/dim]): [/bold]").lower().strip()
                )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted[/dim]")
            return False

        if irreversible:
            if response.lower().strip() == "yes":
                pass  # Fall through to approve
            elif response.lower() in ("d", "deny", "n", "no"):
                try:
                    api.log_gateway_denial(agent=agent, service=service, method=method, path=path)
                except APIError as e:
                    console.print(f"[yellow]Warning: Could not log denial: {e}[/yellow]")
                console.print(f"[red]Denied[/red] - {service} {method} {path}")
                return False
            elif response.lower() in ("l", "later", ""):
                console.print("[dim]Deferred — will re-prompt next session[/dim]")
                return False
            else:
                console.print("[dim]Type yes to approve, d to deny, l for later[/dim]")
                continue
        else:
            if response in ("a", "approve", "y", "yes"):
                pass  # Fall through to approve
            elif response in ("d", "deny", "n", "no"):
                try:
                    api.log_gateway_denial(agent=agent, service=service, method=method, path=path)
                except APIError as e:
                    console.print(f"[yellow]Warning: Could not log denial: {e}[/yellow]")
                console.print(f"[red]Denied[/red] - {service} {method} {path}")
                return False
            elif response in ("l", "later", ""):
                console.print("[dim]Deferred — will re-prompt next session[/dim]")
                return False
            else:
                console.print("[dim]Invalid input. Use: a(pprove), d(eny), l(ater)[/dim]")
                continue

        # Approve — add grant
        try:
            result = api.add_gateway_grant(
                agent=agent,
                service=service,
                method=method,
                path=path,
                lifetime="once",
            )
            grant_id = result.get("grant_id", "?")
            console.print(f"[green]Approved[/green] - {service} {method} {path} (grant {grant_id})")
            return True
        except APIError as e:
            console.print(f"[red]API Error:[/red] {e}")
            return False


def handle_approval(event: dict, api: AdminAPI) -> bool:
    """Handle an approval request interactively.

    Returns True if approved, False if denied/skipped.
    """
    approval = event.get("approval", {})
    details = event.get("details", {})
    fingerprint = approval.get("key", details.get("fingerprint", ""))
    host = event.get("host", approval.get("target", ""))

    # Show the request
    console.print()
    console.print(format_approval_request(event))

    # Get user input
    while True:
        try:
            response = (
                console.input("[bold]Action ([green]a[/green]/[red]d[/red]/[dim]l[/dim]): [/bold]").lower().strip()
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted[/dim]")
            return False

        if response in ("a", "approve", "y", "yes"):
            # Approve - add credential permission to baseline policy
            # fingerprint is already in format "hmac:abc123"
            try:
                result = api.add_approval(
                    destination=host,
                    cred_id=fingerprint,
                )
                status = result.get("status", "unknown")
                if status == "added":
                    console.print(f"[green]Approved[/green] - {fingerprint[:16]}... -> {host}")
                elif status == "exists":
                    console.print("[yellow]Already approved[/yellow]")
                else:
                    console.print(f"[green]OK[/green] - {result}")
                return True
            except APIError as e:
                console.print(f"[red]API Error:[/red] {e}")
                return False

        elif response in ("d", "deny", "n", "no"):
            # Log the denial
            try:
                api.log_denial(
                    destination=host,
                    cred_id=fingerprint,
                    reason="user_denied",
                )
            except APIError as e:
                console.print(f"[yellow]Warning: Could not log denial: {e}[/yellow]")
            console.print(f"[red]Denied[/red] - {fingerprint[:16]}...")
            return False

        elif response in ("l", "later", ""):
            console.print("[dim]Deferred — will re-prompt next session[/dim]")
            return False

        else:
            console.print("[dim]Invalid input. Use: a(pprove), d(eny), l(ater)[/dim]")


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
    # Use approval field to detect events needing attention
    approval = event.get("approval", {})
    if not approval or not approval.get("required"):
        return

    # Deduplicate by key:target
    dedup_key = f"{approval.get('key', '')}:{approval.get('target', '')}"
    if dedup_key in toasted:
        return
    toasted.add(dedup_key)

    # Build toast message from summary
    summary = event.get("summary", "Credential blocked")
    message = f"SafeYolo: {summary}"

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

    Each fingerprint+destination pair is only prompted once per session.
    If you deny a credential and it tries again, you won't be re-prompted
    until you restart 'safeyolo watch'.

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

    # Rolling stats for status summaries (reuses existing RollingStats)
    stats = RollingStats()
    last_status_time = time.time()
    events_since_status = 0
    has_seen_events = False

    # Startup scan: find unresolved approval requests and prompt immediately
    if interactive and api:
        pending = scan_pending_approvals(log_path)
        if pending:
            console.print(f"[bold yellow]{len(pending)} pending approval(s) from before this session:[/bold yellow]")
            console.print()
            for event in pending:
                event_type = event.get("event", "")
                if event_type == "gateway.risky_route":
                    key = _risky_route_dedup_key(event)
                    if key not in seen_fingerprints:
                        seen_fingerprints.add(key)
                        approved = handle_risky_route_approval(event, api)
                        if approved:
                            stats.mark_resolved(key)
                else:
                    # Credential approval
                    approval = event.get("approval", {})
                    key = f"{approval.get('key', '')}:{approval.get('target', '')}"
                    if key not in seen_fingerprints:
                        seen_fingerprints.add(key)
                        approved = handle_approval(event, api)
                        if approved:
                            stats.mark_resolved(key)
            console.print()

    # Print initial idle indicator if no events come quickly
    if not has_seen_events:
        console.print("[dim]Listening... no events yet[/dim]")

    try:
        for event in tail_jsonl(log_path, follow=follow):
            kind = event.get("kind", "")

            # Filter to security/gateway events if requested
            if security_only and kind not in ("security", "gateway"):
                continue

            if not has_seen_events:
                has_seen_events = True

            # Track all events in rolling stats
            stats.add_event(event)

            # Check for events needing approval via approval field
            approval = event.get("approval", {})
            decision = event.get("decision", "")

            if approval and approval.get("required"):
                # Deduplicate by key:target
                dedup_key = f"{approval.get('key', '')}:{approval.get('target', '')}"
                if dedup_key in seen_fingerprints:
                    ts = event.get("ts", "")
                    ts_str = ""
                    if ts:
                        try:
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            ts_str = dt.astimezone().strftime("%H:%M:%S")
                        except (ValueError, AttributeError):
                            ts_str = ts[:19]
                    console.print(f"[dim]{ts_str} Suppressed duplicate: {dedup_key} (already prompted this session)[/dim]")
                    continue
                seen_fingerprints.add(dedup_key)

                # Show status context before prompting
                if events_since_status > 0:
                    _print_interactive_status(stats)
                    events_since_status = 0
                    last_status_time = time.time()

                if interactive and api:
                    approved = handle_approval(event, api)
                    if approved:
                        stats.mark_resolved(dedup_key)
                else:
                    console.print(format_approval_request(event))

            elif event.get("event") == "gateway.risky_route" and decision == "require_approval":
                # Risky route approval — dedup on agent:service:method:path
                dedup_key = _risky_route_dedup_key(event)
                if dedup_key in seen_fingerprints:
                    ts = event.get("ts", "")
                    ts_str = ""
                    if ts:
                        try:
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            ts_str = dt.astimezone().strftime("%H:%M:%S")
                        except (ValueError, AttributeError):
                            ts_str = ts[:19]
                    console.print(f"[dim]{ts_str} Suppressed duplicate: {dedup_key} (already prompted this session)[/dim]")
                    continue
                seen_fingerprints.add(dedup_key)

                # Show status context before prompting
                if events_since_status > 0:
                    _print_interactive_status(stats)
                    events_since_status = 0
                    last_status_time = time.time()

                if interactive and api:
                    approved = handle_risky_route_approval(event, api)
                    if approved:
                        stats.mark_resolved(dedup_key)
                else:
                    _print_event_summary(event)

            elif decision == "allow":
                # Suppress individual allow lines, aggregate in stats
                events_since_status += 1
                now = time.time()
                if now - last_status_time >= STATUS_INTERVAL or events_since_status >= STATUS_BATCH:
                    _print_interactive_status(stats)
                    events_since_status = 0
                    last_status_time = now
            else:
                # Other events - show summary
                _print_event_summary(event)

    except KeyboardInterrupt:
        if events_since_status > 0:
            _print_interactive_status(stats)
        console.print("\n[dim]Stopped watching.[/dim]")


def _print_interactive_status(stats: RollingStats) -> None:
    """Print a compact rolling-window status summary for interactive mode."""
    win_req, win_block, win_warn = stats.window_counts()
    win_allow = win_req - win_block - win_warn

    parts = []
    if win_allow > 0:
        by_host = stats.window_allows_by_host()
        if by_host:
            top_host = max(by_host, key=by_host.get)
            if len(by_host) == 1:
                parts.append(f"[green]{win_allow} allowed[/green] [dim]→ {top_host}[/dim]")
            else:
                others = len(by_host) - 1
                parts.append(f"[green]{win_allow} allowed[/green] [dim]→ {top_host} +{others} more[/dim]")
        else:
            parts.append(f"[green]{win_allow} allowed[/green]")
    if win_block > 0:
        parts.append(f"[red]{win_block} blocked[/red]")
    if win_warn > 0:
        parts.append(f"[yellow]{win_warn} warnings[/yellow]")
    if stats.pending_approvals > 0:
        parts.append(f"[bold red]{stats.pending_approvals} pending[/bold red]")

    if not parts:
        return

    ts = datetime.now().strftime("%H:%M:%S")
    status = " \u2502 ".join(parts)
    console.print(f"[dim]{ts}[/dim] {status} [dim](5m window)[/dim]")


def _print_event_summary(event: dict) -> None:
    """Print a one-line summary of an event."""
    event_type = event.get("event", "unknown")
    ts = event.get("ts", "")
    severity = event.get("severity", "")

    # Format timestamp
    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.astimezone().strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]

    # Color based on severity and kind
    if severity in ("critical", "high"):
        decision = event.get("decision", "")
        if decision in ("deny", "require_approval", "budget_exceeded"):
            style = "red"
        elif decision == "warn":
            style = "yellow"
        else:
            style = "cyan"
    elif event.get("kind") == "admin":
        style = "magenta"
    else:
        style = "dim"

    # Use summary field from event envelope
    summary = event.get("summary", "")
    if not summary:
        # Fallback for legacy events
        summary_parts = []
        for key in ("decision", "host", "addon"):
            if key in event:
                summary_parts.append(f"{key}={event[key]}")
        summary = " ".join(summary_parts[:4])

    from rich.markup import escape

    console.print(f"[dim]{timestamp_str}[/dim] [{style}]{event_type}[/{style}] {escape(summary)}")
