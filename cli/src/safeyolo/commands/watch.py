"""Watch command - monitor logs and handle approval requests."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
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

# Batch mode: how long to accumulate events before flushing
BATCH_WINDOW = 2.0  # seconds


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


def tail_jsonl(path: Path, follow: bool = True, tick_interval: float = 0):
    """Tail a JSONL file, yielding parsed events.

    Handles log rotation and proxy restarts: if the file is replaced
    (inode changes) or truncated, reopens from the beginning of the
    new file.

    Args:
        path: Path to JSONL file
        follow: If True, keep watching for new lines
        tick_interval: If >0 and idle, yield None every tick_interval seconds

    Yields:
        Parsed JSON objects from each line, or None for tick events
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
    idle_cycles = 0  # counter for tick generation
    tick_cycles = int(tick_interval / 0.1) if tick_interval > 0 else 0

    with open(path) as f:
        original_inode = os.fstat(f.fileno()).st_ino

        # Start from end for follow mode
        if follow:
            f.seek(0, 2)  # Seek to end

        while True:
            line = f.readline()
            if line:
                check_interval = 0
                idle_cycles = 0
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue  # Skip malformed lines
            elif follow:
                time.sleep(0.1)
                check_interval += 1
                idle_cycles += 1

                # Yield tick if configured and enough idle time has passed
                if tick_cycles and idle_cycles >= tick_cycles:
                    idle_cycles = 0
                    yield None

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


# ---------------------------------------------------------------------------
# Batch approval infrastructure
# ---------------------------------------------------------------------------


@dataclass
class BatchItem:
    """A single pending approval in a batch."""

    index: int  # 1-based display number
    event: dict  # original event
    dedup_key: str  # from approval.key:approval.target
    approval_type: str  # from approval.approval_type
    irreversible: bool  # from details.irreversible (False if absent)


@dataclass
class ApprovalDispatch:
    """Per-approval-type handlers for approve/deny/format."""

    approve: Callable[[dict, AdminAPI], str | None]  # returns grant_id/status or None
    deny: Callable[[dict, AdminAPI], None]
    format_row: Callable[[dict], tuple[str, str, str, str]]  # agent, action, risk, description
    format_detail: Callable[[dict], Panel]  # full panel for review mode


def _credential_approve(event: dict, api: AdminAPI) -> str | None:
    approval = event.get("approval", {})
    details = event.get("details", {})
    fingerprint = approval.get("key", details.get("fingerprint", ""))
    host = event.get("host", approval.get("target", ""))
    result = api.add_approval(destination=host, cred_id=fingerprint)
    return result.get("status", "ok")


def _credential_deny(event: dict, api: AdminAPI) -> None:
    approval = event.get("approval", {})
    details = event.get("details", {})
    fingerprint = approval.get("key", details.get("fingerprint", ""))
    host = event.get("host", approval.get("target", ""))
    api.log_denial(destination=host, cred_id=fingerprint, reason="user_denied")


def _credential_format_row(event: dict) -> tuple[str, str, str, str]:
    approval = event.get("approval", {})
    details = event.get("details", {})
    agent = event.get("agent", "\u2014")
    rule = details.get("rule", approval.get("approval_type", "unknown"))
    host = event.get("host", approval.get("target", "unknown"))
    action = f"{rule} cred \u2192 {host}"
    risk = "credential routing"
    description = details.get("reason", "")
    return (agent, action, risk, description)


def _gateway_approve(event: dict, api: AdminAPI) -> str | None:
    details = event.get("details", {})
    agent = event.get("agent", "unknown")
    service = details.get("service", "unknown")
    method = details.get("method", "")
    path = details.get("path", details.get("risky_route", ""))
    result = api.add_gateway_grant(
        agent=agent, service=service, method=method, path=path, lifetime="once",
    )
    return result.get("grant_id")


def _gateway_deny(event: dict, api: AdminAPI) -> None:
    details = event.get("details", {})
    agent = event.get("agent", "unknown")
    service = details.get("service", "unknown")
    method = details.get("method", "")
    path = details.get("path", details.get("risky_route", ""))
    api.log_gateway_denial(agent=agent, service=service, method=method, path=path)


def _gateway_format_row(event: dict) -> tuple[str, str, str, str]:
    details = event.get("details", {})
    agent = event.get("agent", "\u2014")
    service = details.get("service", "unknown")
    method = details.get("method", "")
    path = details.get("path", "")
    action = f"{service} {method} {path}"
    # Build risk string from tactics
    tactics = details.get("tactics", [])
    risk_parts = [TACTIC_LABELS.get(t, t) for t in tactics] if tactics else []
    risk = ", ".join(risk_parts) if risk_parts else "risky route"
    description = details.get("description", "")
    return (agent, action, risk, description)


def _service_format_row(event: dict) -> tuple[str, str, str, str]:
    # Unused in batch table (service items get special rendering),
    # but kept for API compatibility with ApprovalDispatch.
    approval = event.get("approval", {})
    agent = event.get("agent", "\u2014")
    target = approval.get("target", "?")
    scope = approval.get("scope_hint", {})
    capability = scope.get("capability", "")
    action = f"{target}/{capability}" if capability else target
    risk = "service access"
    description = event.get("summary", "")
    return (agent, action, risk, description)


def _service_format_detail(event: dict) -> Panel:
    """Format a service access request as a Rich panel."""

    approval = event.get("approval", {})
    scope = approval.get("scope_hint", {})
    agent = event.get("agent", "unknown")
    service = approval.get("target", "unknown")
    capability = scope.get("capability", "")
    reason = scope.get("reason", "") or event.get("summary", "")
    ts = event.get("ts", "")

    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.astimezone().strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Service", f"[cyan]{escape(service)}[/cyan]")
    if capability:
        table.add_row("Capability", escape(capability))
    if reason:
        table.add_row("Reason", escape(reason))
    table.add_row("", "")
    table.add_row("", "[dim]This will permanently bind a credential to this agent.[/dim]")

    title = (
        f"[bold yellow]{escape(agent)}[/bold yellow]"
        f" requests authenticated access"
        f" [dim]{timestamp_str}[/dim]"
    )

    return Panel(
        table,
        title=title,
        subtitle="[green][A]uthorize[/green] \u00b7 [red][D]eny[/red] \u00b7 [dim][L]ater[/dim]",
        border_style="yellow",
    )


def _service_approve(event: dict, api: AdminAPI) -> str | None:
    approval = event.get("approval", {})
    scope = approval.get("scope_hint", {})
    agent = event.get("agent", "")
    service = approval.get("target", "")
    capability = scope.get("capability", "")

    if not agent or not service:
        raise NotImplementedError(
            "Service access event missing agent or service — "
            "run `safeyolo agent authorize` on the host instead"
        )

    try:
        if not capability:
            capability = console.input(
                f"[bold]Capability for {escape(service)}:[/bold] "
            ).strip()
            if not capability:
                raise NotImplementedError("Capability required")

        # Credential flow: pick existing or create new
        cred_name = _pick_or_create_credential(service)
        if not cred_name:
            raise NotImplementedError("Credential required")

    except (KeyboardInterrupt, EOFError):
        raise NotImplementedError("Interrupted")

    result = api.authorize_service(
        agent=agent,
        service=service,
        capability=capability,
        credential=cred_name,
    )
    return result.get("status", "authorized")


def _pick_or_create_credential(service: str) -> str | None:
    """Interactive credential selection: pick existing or create new.

    Returns credential name, or None if cancelled.
    """
    from ._service_discovery import find_service
    from .vault import _load_vault

    try:
        vault, VaultCredential = _load_vault()
    except (OSError, ValueError) as e:
        console.print(f"[red]Error loading vault:[/red] {e}")
        return None

    # Look up auth type from service definition
    svc = find_service(service)
    auth_type = "bearer"
    if svc:
        auth_type = svc.get("auth", {}).get("type", "bearer")

    AUTH_TYPE_LABELS = {
        "bearer": "Bearer token",
        "api_key": "API key",
        "oauth2": "OAuth2 token",
    }
    type_label = AUTH_TYPE_LABELS.get(auth_type, auth_type)

    existing_names = vault.list_names()
    matching = [n for n in existing_names if n.startswith(f"{service}-")]

    if matching:
        console.print()
        for i, n in enumerate(matching, 1):
            console.print(f"  [{i}] {escape(n)}")
        console.print(f"  [{len(matching) + 1}] Enter new {type_label.lower()}")
        choice = console.input(f"[bold]Select credential [1-{len(matching) + 1}]:[/bold] ").strip()
        if not choice:
            choice = "1"
        try:
            idx = int(choice) - 1
            if idx < 0 or idx > len(matching):
                raise ValueError
            if idx < len(matching):
                return matching[idx]
        except ValueError:
            console.print("[dim]Invalid selection[/dim]")
            return None
    # Fall through: no matching creds, or user chose "enter new"

    cred_value = console.input(f"[bold]{type_label}:[/bold] ", password=True).strip()
    if not cred_value:
        console.print("[dim]No value provided — cancelled[/dim]")
        return None

    from .agent import _auto_credential_name

    cred_name = _auto_credential_name(service, existing_names)
    cred = VaultCredential(name=cred_name, type=auth_type, value=cred_value)
    vault.store(cred)
    console.print(
        f"[green]Credential stored:[/green] {escape(cred_name)} in vault. "
        f"To remove: [bold]safeyolo vault remove {escape(cred_name)}[/bold]"
    )
    return cred_name


def _service_deny(event: dict, api: AdminAPI) -> None:
    # Log the denial via the generic denial endpoint
    approval = event.get("approval", {})
    agent = event.get("agent", "unknown")
    target = approval.get("target", "unknown")
    api.log_denial(
        destination=f"gateway:{target}",
        cred_id=f"{agent}:service_access",
        reason="user_denied",
    )


def _unsupported_approve(event: dict, api: AdminAPI) -> str | None:
    raise NotImplementedError(
        f"Cannot approve unknown approval_type {event.get('approval', {}).get('approval_type')!r} "
        "in batch mode — use individual review (r<N>) instead"
    )


def _unsupported_deny(event: dict, api: AdminAPI) -> None:
    raise NotImplementedError(
        f"Cannot deny unknown approval_type {event.get('approval', {}).get('approval_type')!r} "
        "in batch mode — use individual review (r<N>) instead"
    )


def _fallback_format_row(event: dict) -> tuple[str, str, str, str]:
    approval = event.get("approval", {})
    agent = event.get("agent", "\u2014")
    action = f"{approval.get('approval_type', '?')} \u2192 {approval.get('target', '?')}"
    risk = "unknown"
    description = event.get("summary", "")
    return (agent, action, risk, description)


def _fallback_format_detail(event: dict) -> Panel:
    """Generic detail panel for unknown approval types."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")
    for key in ("event", "agent", "host", "summary"):
        if event.get(key):
            table.add_row(key.title(), str(event[key]))
    approval = event.get("approval", {})
    for key in ("approval_type", "key", "target"):
        if approval.get(key):
            table.add_row(f"approval.{key}", str(approval[key]))
    return Panel(table, title="[bold]Unknown Approval Type[/bold]", border_style="yellow")


FALLBACK_DISPATCH = ApprovalDispatch(
    approve=_unsupported_approve,
    deny=_unsupported_deny,
    format_row=_fallback_format_row,
    format_detail=_fallback_format_detail,
)

def _contract_binding_format_row(event: dict) -> tuple[str, str, str, str]:
    approval = event.get("approval", {})
    scope = approval.get("scope_hint", {})
    agent = event.get("agent", "\u2014")
    service = approval.get("target", "?")
    capability = scope.get("capability", "")
    bindings = scope.get("bindings", {})
    binding_summary = ", ".join(f"{v}" for v in bindings.values()) if bindings else ""
    action = f"{service}/{capability}" if capability else service
    if binding_summary:
        action += f" [{binding_summary}]"
    risk = "contract binding"
    description = ""
    return (agent, action, risk, description)


def _contract_binding_format_detail(event: dict) -> Panel:
    """System-authored panel for contract binding approval. No agent reason text."""
    approval = event.get("approval", {})
    scope = approval.get("scope_hint", {})
    agent = event.get("agent", "unknown")
    service = approval.get("target", "unknown")
    capability = scope.get("capability", "")
    bindings = scope.get("bindings", {})
    grantable_ops = scope.get("grantable_operations", [])
    ts = event.get("ts", "")

    timestamp_str = ""
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            timestamp_str = dt.astimezone().strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            timestamp_str = ts[:19]

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    table.add_row("Capability", escape(capability))
    # Show binding values (scope)
    binding_display = ", ".join(f"{v}" for v in bindings.values()) if bindings else "\u2014"
    table.add_row("Scope", escape(binding_display))
    # Show grantable operations
    ops_display = ", ".join(grantable_ops) if grantable_ops else "\u2014"
    table.add_row("Operations", escape(ops_display))
    # Risk line
    table.add_row("Risk", f"can {escape(', '.join(grantable_ops))} in scope")
    table.add_row("Assessment", "within contract, no conflicts detected")

    title = (
        f"[bold yellow]{escape(agent)}[/bold yellow]"
        f" requests {escape(capability)}"
        f" ({escape(service)})"
        f" [dim]{timestamp_str}[/dim]"
    )

    return Panel(
        table,
        title=title,
        subtitle="[green][A]pprove[/green] \u00b7 [red][D]eny[/red] \u00b7 [dim][L]ater[/dim]",
        border_style="yellow",
    )


def _contract_binding_approve(event: dict, api: AdminAPI) -> str | None:
    approval = event.get("approval", {})
    scope = approval.get("scope_hint", {})
    agent = event.get("agent", "")
    service = approval.get("target", "")
    capability = scope.get("capability", "")
    template = scope.get("template", "")
    bindings = scope.get("bindings", {})
    grantable_ops = scope.get("grantable_operations", [])

    if not agent or not service or not capability:
        raise NotImplementedError(
            "Contract binding event missing agent, service, or capability"
        )

    # Approve the contract binding
    result = api.approve_contract_binding(
        agent=agent,
        service=service,
        capability=capability,
        template=template,
        bindings=bindings,
        grantable_operations=grantable_ops,
    )

    # Contract binding and service authorization are separate concerns.
    # If the agent isn't already authorized for this service, a separate
    # "service" approval event will appear in watch for credential selection.

    return result.get("status", "bound")


def _contract_binding_deny(event: dict, api: AdminAPI) -> None:
    approval = event.get("approval", {})
    agent = event.get("agent", "unknown")
    target = approval.get("target", "unknown")
    api.log_denial(
        destination=f"gateway:{target}",
        cred_id=f"{agent}:contract_binding",
        reason="user_denied",
    )



def _dedup_key_from_approval(event: dict) -> str:
    """Derive dedup key from the approval field on an event."""
    approval = event.get("approval", {})
    return f"{approval.get('key', '')}:{approval.get('target', '')}"


def build_batch_items(events: list[dict]) -> list[BatchItem]:
    """Convert raw events into BatchItems with 1-based indexing."""
    items: list[BatchItem] = []
    for i, event in enumerate(events, 1):
        approval = event.get("approval", {})
        details = event.get("details", {})
        items.append(BatchItem(
            index=i,
            event=event,
            dedup_key=_dedup_key_from_approval(event),
            approval_type=approval.get("approval_type", "unknown"),
            irreversible=details.get("irreversible", False),
        ))
    return items


def _format_batch_table(items: list[BatchItem]) -> Panel:
    """Render a batch approval table with risk signals."""
    table = Table(show_header=True, box=None, padding=(0, 1))
    table.add_column("#", style="dim", width=3, justify="right")
    table.add_column("Agent", min_width=8)
    table.add_column("Action", min_width=20)
    table.add_column("Risk", min_width=12)

    for item in items:
        if item.approval_type == "service":
            # Service auth items break the grid — visually distinct
            approval = item.event.get("approval", {})
            scope = approval.get("scope_hint", {})
            agent = item.event.get("agent", "?")
            service = approval.get("target", "?")
            capability = scope.get("capability", "")
            reason = scope.get("reason", "") or item.event.get("summary", "")

            cap_str = f" ({escape(capability)})" if capability else ""
            line = (
                f"[bold]{escape(agent)}[/bold] requests "
                f"[bold yellow]authenticated access[/bold yellow] to "
                f"[cyan]{escape(service)}[/cyan]{cap_str}"
            )

            table.add_row("", "", "", "", end_section=True)
            table.add_row(f"[bold yellow]{item.index}[/bold yellow]", line, "", "")
            if reason:
                table.add_row("", f'  [dim]"{escape(reason)}"[/dim]', "", "")
            table.add_row("", "", "", "", end_section=True)
            continue

        dispatch = DISPATCH.get(item.approval_type, FALLBACK_DISPATCH)
        agent, action, risk, description = dispatch.format_row(item.event)

        # Append irreversible marker
        risk_display = escape(risk)
        if item.irreversible:
            risk_display += "  [bold red]\u26a0 IRREVERSIBLE[/bold red]"

        table.add_row(str(item.index), f"[bold]{escape(agent)}[/bold]", escape(action), risk_display)

        # Description sub-row if present
        if description:
            table.add_row("", "", f"  [dim]\u2514 {escape(description)}[/dim]", "")

    title = f"[bold yellow]{len(items)} pending approval(s)[/bold yellow]"
    subtitle = "[green]a[/green]=approve all  [red]d[/red]=deny all  [dim]l[/dim]=later  [dim]#,#[/dim]=pick items  [dim]r#[/dim]=review item"

    return Panel(table, title=title, subtitle=subtitle, border_style="yellow")


_SELECTION_RE = re.compile(r"^r(\d+)$")


def parse_selection(raw: str, max_index: int) -> str | tuple[str, int] | list[int]:
    """Parse batch input into an action.

    Returns:
        "a" | "d" | "l" | ("review", int) | list[int]

    Raises:
        ValueError on invalid input.
    """
    raw = raw.strip().lower()

    if raw in ("a", "approve", "y", "yes"):
        return "a"
    if raw in ("d", "deny", "n", "no"):
        return "d"
    if raw in ("l", "later", ""):
        return "l"

    # Review single item: r3
    m = _SELECTION_RE.match(raw)
    if m:
        idx = int(m.group(1))
        if idx < 1 or idx > max_index:
            raise ValueError(f"Item {idx} out of range (1-{max_index})")
        return ("review", idx)

    # Selection: 1,3,5 or 1-3,5
    indices: set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise ValueError(f"Invalid range: {part!r}")
            if lo > hi:
                raise ValueError(f"Invalid range: {part!r}")
            for i in range(lo, hi + 1):
                indices.add(i)
        else:
            try:
                indices.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid input: {raw!r}")

    if not indices:
        raise ValueError(f"Invalid input: {raw!r}")

    # Validate range
    for idx in indices:
        if idx < 1 or idx > max_index:
            raise ValueError(f"Item {idx} out of range (1-{max_index})")

    return sorted(indices)


def handle_batch(
    items: list[BatchItem],
    api: AdminAPI,
    stats: RollingStats,
) -> None:
    """Handle a batch of pending approvals interactively.

    Single item: delegates to existing per-type handler.
    Multi-item: shows batch table and processes selections.
    """
    if not items:
        return

    # Single item — delegate to existing handler (no UX change)
    if len(items) == 1:
        item = items[0]
        approved = _prompt_single_item(item, api)
        if approved:
            stats.mark_resolved(item.dedup_key)
        return

    # Multi-item batch
    console.print()
    console.print(_format_batch_table(items))

    while True:
        try:
            raw = console.input(
                "[bold]Action ([green]a[/green]/[red]d[/red]/[dim]l[/dim]/select/review): [/bold]"
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted — all deferred[/dim]")
            return

        try:
            action = parse_selection(raw, len(items))
        except ValueError as e:
            console.print(f"[dim]{e}[/dim]")
            continue

        if action == "a":
            _batch_approve_all(items, api, stats)
            return
        elif action == "d":
            _batch_deny_all(items, api, stats)
            return
        elif action == "l":
            console.print(f"[dim]Deferred {len(items)} item(s)[/dim]")
            return
        elif isinstance(action, tuple) and action[0] == "review":
            idx = action[1]
            item = items[idx - 1]
            approved = _prompt_single_item(item, api)
            if approved:
                stats.mark_resolved(item.dedup_key)
            # Remove handled item, re-number remaining
            items = [it for it in items if it is not item]
            if not items:
                return
            for i, it in enumerate(items, 1):
                it.index = i
            console.print()
            console.print(_format_batch_table(items))
            continue
        elif isinstance(action, list):
            remaining = _batch_select(items, action, api, stats)
            if not remaining:
                return
            # Re-number and re-display remaining items
            for i, item in enumerate(remaining, 1):
                item.index = i
            items = remaining
            console.print()
            console.print(_format_batch_table(items))
            continue


def _prompt_single_item(item: BatchItem, api: AdminAPI) -> bool:
    """Prompt for a single item using the appropriate per-type handler.

    Returns True if approved.
    """
    dispatch = DISPATCH.get(item.approval_type, FALLBACK_DISPATCH)

    if item.approval_type == "gateway_route":
        return handle_risky_route_approval(item.event, api)
    elif item.approval_type == "credential":
        return handle_approval(item.event, api)
    elif item.approval_type in ("service", "contract_binding"):
        console.print()
        console.print(dispatch.format_detail(item.event))
        while True:
            try:
                response = console.input(
                    "[bold][green]a[/green]uthorize / [red]d[/red]eny / [dim]l[/dim]ater: [/bold]"
                ).lower().strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Interrupted[/dim]")
                return False
            if response in ("a", "authorize", "y", "yes"):
                try:
                    dispatch.approve(item.event, api)
                    console.print("[green]Authorized[/green]")
                    return True
                except (APIError, NotImplementedError) as e:
                    console.print(f"[red]Error:[/red] {escape(str(e))}")
                    return False
            elif response in ("d", "deny", "n", "no"):
                try:
                    dispatch.deny(item.event, api)
                except (APIError, NotImplementedError) as e:
                    console.print(f"[yellow]Warning:[/yellow] {escape(str(e))}")
                console.print("[red]Denied[/red]")
                return False
            elif response in ("l", "later", ""):
                console.print("[dim]Deferred[/dim]")
                return False
            else:
                console.print("[dim]Invalid input. Use: a(uthorize), d(eny), l(ater)[/dim]")
    else:
        # Fallback: show detail and prompt a/d/l
        console.print()
        console.print(dispatch.format_detail(item.event))
        while True:
            try:
                response = console.input(
                    "[bold]Action ([green]a[/green]/[red]d[/red]/[dim]l[/dim]): [/bold]"
                ).lower().strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Interrupted[/dim]")
                return False
            if response in ("a", "approve", "y", "yes"):
                try:
                    dispatch.approve(item.event, api)
                    console.print("[green]Approved[/green]")
                    return True
                except (APIError, NotImplementedError) as e:
                    console.print(f"[red]Error:[/red] {escape(str(e))}")
                    return False
            elif response in ("d", "deny", "n", "no"):
                try:
                    dispatch.deny(item.event, api)
                except (APIError, NotImplementedError) as e:
                    console.print(f"[yellow]Warning:[/yellow] {escape(str(e))}")
                console.print("[red]Denied[/red]")
                return False
            elif response in ("l", "later", ""):
                console.print("[dim]Deferred[/dim]")
                return False
            else:
                console.print("[dim]Invalid input. Use: a(pprove), d(eny), l(ater)[/dim]")


def _batch_approve_all(
    items: list[BatchItem],
    api: AdminAPI,
    stats: RollingStats,
) -> None:
    """Approve all items; irreversible ones get individual confirmation."""
    safe = [it for it in items if not it.irreversible]
    dangerous = [it for it in items if it.irreversible]

    # Approve safe items in bulk
    approved_count = 0
    for item in safe:
        dispatch = DISPATCH.get(item.approval_type, FALLBACK_DISPATCH)
        try:
            dispatch.approve(item.event, api)
            stats.mark_resolved(item.dedup_key)
            approved_count += 1
        except (APIError, NotImplementedError) as e:
            console.print(f"[red]Error approving #{item.index}:[/red] {escape(str(e))}")

    if approved_count:
        console.print(f"[green]Approved {approved_count} item(s)[/green]")

    # Irreversible items get individual confirmation
    if dangerous:
        console.print(
            f"\n[bold red]{len(dangerous)} irreversible item(s) require individual confirmation:[/bold red]"
        )
        for item in dangerous:
            dispatch = DISPATCH.get(item.approval_type, FALLBACK_DISPATCH)
            console.print()
            console.print(dispatch.format_detail(item.event))
            while True:
                try:
                    response = console.input(
                        "[bold]Type [yellow]yes[/yellow] to approve, "
                        "[red]d[/red] to deny, [dim]l[/dim]ater: [/bold]"
                    ).strip()
                except (KeyboardInterrupt, EOFError):
                    console.print("\n[dim]Remaining items deferred[/dim]")
                    return
                if response.lower() == "yes":
                    try:
                        dispatch.approve(item.event, api)
                        stats.mark_resolved(item.dedup_key)
                        console.print(f"[green]Approved #{item.index}[/green]")
                    except (APIError, NotImplementedError) as e:
                        console.print(f"[red]Error:[/red] {escape(str(e))}")
                    break
                elif response.lower() in ("d", "deny", "n", "no"):
                    try:
                        dispatch.deny(item.event, api)
                        stats.mark_resolved(item.dedup_key)
                    except (APIError, NotImplementedError) as e:
                        console.print(f"[yellow]Warning:[/yellow] {escape(str(e))}")
                    console.print(f"[red]Denied #{item.index}[/red]")
                    break
                elif response.lower() in ("l", "later", ""):
                    console.print(f"[dim]Deferred #{item.index}[/dim]")
                    break
                else:
                    console.print("[dim]Type yes to approve, d to deny, l for later[/dim]")


def _batch_deny_all(
    items: list[BatchItem],
    api: AdminAPI,
    stats: RollingStats,
) -> None:
    """Deny all items in the batch."""
    denied_count = 0
    for item in items:
        dispatch = DISPATCH.get(item.approval_type, FALLBACK_DISPATCH)
        try:
            dispatch.deny(item.event, api)
            stats.mark_resolved(item.dedup_key)
            denied_count += 1
        except (APIError, NotImplementedError) as e:
            console.print(f"[red]Error denying #{item.index}:[/red] {escape(str(e))}")
    console.print(f"[red]Denied {denied_count} item(s)[/red]")


def _batch_select(
    items: list[BatchItem],
    indices: list[int],
    api: AdminAPI,
    stats: RollingStats,
) -> list[BatchItem]:
    """Process selected items individually; return remaining items."""
    selected = set(indices)

    remaining: list[BatchItem] = []
    for item in items:
        if item.index not in selected:
            remaining.append(item)
            continue
        approved = _prompt_single_item(item, api)
        if approved:
            stats.mark_resolved(item.dedup_key)

    return remaining


def _resolved_key_from_admin_event(event: dict) -> str | None:
    """Extract the dedup key that an admin action resolved, if possible."""
    event_type = event.get("event", "")
    details = event.get("details", {})

    if event_type in ("admin.approval_added", "admin.denial"):
        # Credential resolution: details has destination + cred_id
        cred_id = details.get("cred_id", "")
        destination = details.get("destination", "")
        if cred_id and destination:
            # Gateway denials use destination="gateway:{service}", cred_id="{agent}:{method}:{path}"
            if destination.startswith("gateway:"):
                parts = cred_id.split(":", 2)
                if len(parts) == 3:
                    agent, method, path = parts
                    service = destination.removeprefix("gateway:")
                    return f"gw:{agent}:{service}:{method}:{path}:{service}"
            return f"{cred_id}:{destination}"
        return None

    if event_type == "admin.gateway_grant":
        agent = details.get("agent", "")
        service = details.get("service", "")
        method = details.get("method", "")
        path = details.get("path", "")
        if agent and service:
            return f"gw:{agent}:{service}:{method}:{path}:{service}"
        return None

    if event_type in ("admin.agent_service_authorized", "admin.agent_service_revoked"):
        agent = details.get("agent", "")
        service = details.get("service", "")
        if agent and service:
            return f"{agent}:{service}:{service}"
        return None

    if event_type == "admin.contract_binding_approved":
        agent = details.get("agent", "")
        service = details.get("service", "")
        capability = details.get("capability", "")
        if agent and service and capability:
            return f"{agent}:{service}:{capability}:{service}"
        return None

    return None


def scan_pending_approvals(log_path: Path) -> tuple[list[dict], set[str]]:
    """Scan log backwards for unresolved approval requests.

    All approval events are detected via the ``approval.required`` field.
    Dedup key is always ``approval.key:approval.target``.

    Operator actions (grants, approvals, denials) are tracked individually
    so that selectively processing some items doesn't mask others.

    Returns:
        (pending_events, resolved_keys) — the resolved keys are needed by the
        caller to seed its live-event dedup set so that retries of credentials
        already acted on don't re-prompt.
    """
    if not log_path.exists():
        return [], set()

    # Read lines from file (we need to scan backwards, so read all then reverse)
    # Bounded: only keep last 50K lines to avoid reading huge files
    MAX_SCAN_LINES = 50_000
    recent_lines: deque[str] = deque(maxlen=MAX_SCAN_LINES)
    try:
        with open(log_path) as f:
            for line in f:
                recent_lines.append(line)
    except Exception as e:
        console.print(f"[yellow]Warning:[/yellow] Failed to scan log for pending approvals: {escape(str(e))}")
        return [], set()

    # Two-pass scan: first collect all resolution keys, then filter approvals.
    # This avoids a bug where a recent approval event (retry after denial) is
    # encountered before its corresponding denial when scanning backwards,
    # causing it to be incorrectly treated as pending.
    parsed_events: list[dict] = []
    resolved_keys: set[str] = set()

    for line in reversed(recent_lines):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        parsed_events.append(event)

        resolved_key = _resolved_key_from_admin_event(event)
        if resolved_key:
            resolved_keys.add(resolved_key)

    # Pass 2: collect unresolved approval requests (most-recent-first dedup)
    pending_blocks: dict[str, dict] = {}  # dedup_key -> event
    for event in parsed_events:
        approval = event.get("approval", {})
        if approval and approval.get("required"):
            key = _dedup_key_from_approval(event)
            if key not in pending_blocks and key not in resolved_keys:
                pending_blocks[key] = event

    # Sort by timestamp (oldest first) so prompts appear in chronological order
    pending = list(pending_blocks.values())
    pending.sort(key=lambda e: e.get("ts", ""))

    return pending, resolved_keys


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

    table.add_row("Credential", f"[bold]{escape(rule)}[/bold]")
    table.add_row("Destination", f"[cyan]{escape(host)}[/cyan]")
    table.add_row("Credential ID", f"[dim]{escape(fingerprint)}[/dim] [dim italic](same ID = same key)[/]")
    if client_ip:
        table.add_row("Client", escape(client_ip))
    if location:
        table.add_row("Location", escape(location))
    if confidence:
        table.add_row("Confidence", escape(confidence))
    if reason:
        table.add_row("Reason", f"[yellow]{escape(reason)}[/yellow]")

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

    table.add_row("Agent", f"[bold]{escape(agent)}[/bold]")
    table.add_row("Service", f"[cyan]{escape(service)}[/cyan]")
    if capability:
        table.add_row("Capability", escape(capability))
    display_path = path or risky_route_pattern
    table.add_row("Route", f"[bold]{escape(method)} {escape(display_path)}[/bold]")
    if description:
        table.add_row("Description", escape(description))
    if tactics:
        labeled = ", ".join(f"{escape(t)} ({escape(TACTIC_LABELS.get(t, t))})" for t in tactics)
        table.add_row("Tactics", labeled)
    if enables:
        labeled = ", ".join(f"{escape(e)} ({escape(TACTIC_LABELS.get(e, e))})" for e in enables)
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


# DISPATCH must be defined after format_approval_request and
# format_risky_route_approval so the names resolve at module load time.
DISPATCH: dict[str, ApprovalDispatch] = {
    "credential": ApprovalDispatch(
        approve=_credential_approve,
        deny=_credential_deny,
        format_row=_credential_format_row,
        format_detail=format_approval_request,
    ),
    "gateway_route": ApprovalDispatch(
        approve=_gateway_approve,
        deny=_gateway_deny,
        format_row=_gateway_format_row,
        format_detail=format_risky_route_approval,
    ),
    "service": ApprovalDispatch(
        approve=_service_approve,
        deny=_service_deny,
        format_row=_service_format_row,
        format_detail=_service_format_detail,
    ),
    "contract_binding": ApprovalDispatch(
        approve=_contract_binding_approve,
        deny=_contract_binding_deny,
        format_row=_contract_binding_format_row,
        format_detail=_contract_binding_format_detail,
    ),
}


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

    # Startup scan: find unresolved approval requests and prompt as batch.
    # Seed seen_fingerprints with resolved keys so that live retries of
    # already-denied/approved credentials are suppressed immediately.
    if interactive and api:
        pending, resolved_keys = scan_pending_approvals(log_path)
        seen_fingerprints.update(resolved_keys)
        if pending:
            console.print(f"[bold yellow]{len(pending)} pending approval(s) from before this session:[/bold yellow]")
            items = build_batch_items(pending)
            for item in items:
                seen_fingerprints.add(item.dedup_key)
            handle_batch(items, api, stats)
            console.print()

    # Print initial idle indicator if no events come quickly
    if not has_seen_events:
        console.print("[dim]Listening... no events yet[/dim]")

    # Accumulation buffer for batch flushing
    pending_batch: list[dict] = []
    batch_deadline: float | None = None

    def _flush_batch() -> None:
        """Flush accumulated approval events as a batch."""
        nonlocal pending_batch, batch_deadline
        if not pending_batch:
            return

        if events_since_status > 0:
            _print_interactive_status(stats)

        if interactive and api:
            items = build_batch_items(pending_batch)
            for item in items:
                seen_fingerprints.add(item.dedup_key)
            handle_batch(items, api, stats)
        else:
            # Non-interactive: just display each one
            for ev in pending_batch:
                approval = ev.get("approval", {})
                atype = approval.get("approval_type", "")
                dispatch = DISPATCH.get(atype, FALLBACK_DISPATCH)
                console.print(dispatch.format_detail(ev))

        pending_batch = []
        batch_deadline = None

    try:
        for event in tail_jsonl(log_path, follow=follow, tick_interval=0.5):
            # Tick event (None) — check if batch window expired
            if event is None:
                if batch_deadline is not None and time.time() >= batch_deadline:
                    _flush_batch()
                continue

            kind = event.get("kind", "")

            # Filter to security/gateway events if requested
            # Proxy lifecycle events always pass — essential context
            event_type = event.get("event", "")
            if security_only and kind not in ("security", "gateway") and event_type not in ("ops.proxy_start", "ops.proxy_stop"):
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
                dedup_key = _dedup_key_from_approval(event)
                if dedup_key in seen_fingerprints:
                    ts = event.get("ts", "")
                    ts_str = ""
                    if ts:
                        try:
                            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                            ts_str = dt.astimezone().strftime("%H:%M:%S")
                        except (ValueError, AttributeError):
                            ts_str = ts[:19]
                    console.print(f"[dim]{ts_str} Suppressed duplicate: {escape(dedup_key)} (already prompted this session)[/dim]")
                    continue
                # Don't add to seen_fingerprints yet — that happens at flush
                pending_batch.append(event)
                if batch_deadline is None:
                    batch_deadline = time.time() + BATCH_WINDOW

            elif decision == "allow":
                # Suppress individual allow lines, aggregate in stats
                events_since_status += 1
                now = time.time()
                if now - last_status_time >= STATUS_INTERVAL or events_since_status >= STATUS_BATCH:
                    _print_interactive_status(stats)
                    events_since_status = 0
                    last_status_time = now
                # Check batch deadline on non-approval events too
                if batch_deadline is not None and time.time() >= batch_deadline:
                    _flush_batch()
            else:
                # Other events - show summary
                _print_event_summary(event)
                # Check batch deadline
                if batch_deadline is not None and time.time() >= batch_deadline:
                    _flush_batch()

    except KeyboardInterrupt:
        # Flush any pending batch before exit
        if pending_batch:
            _flush_batch()
        elif events_since_status > 0:
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

    agent = event.get("agent", "")
    agent_prefix = f"[bold]{escape(agent)}[/bold] " if agent else ""
    console.print(f"[dim]{timestamp_str}[/dim] [{style}]{event_type}[/{style}] {agent_prefix}{escape(summary)}")
