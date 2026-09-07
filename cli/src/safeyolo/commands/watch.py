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
from datetime import UTC, datetime, timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from .. import operator_approvals
from .._tactics import TACTIC_LABELS
from ..config import get_logs_dir

console = Console()


class _LazyModule:
    """Resolve a command-only module on its first attribute access."""

    def __init__(self, module_name: str) -> None:
        self.module_name = module_name

    def __getattr__(self, name: str):
        from importlib import import_module

        module = import_module(self.module_name)
        return getattr(module, name)


admin_api = _LazyModule("safeyolo.api")
audit_schema = _LazyModule("safeyolo.core.audit_schema")
audit_stream = _LazyModule("safeyolo.core.audit_stream")

# Default status file location
STATUS_FILE = Path.home() / ".cache" / "safeyolo" / "tmux_status.txt"

# Interactive mode: how often to print status summaries
STATUS_INTERVAL = 10  # seconds between status lines
STATUS_BATCH = 10  # or after this many suppressed allow events

# Batch mode: how long to accumulate events before flushing
BATCH_WINDOW = 2.0  # seconds

# Schema-drift warnings: track how many we've emitted to avoid log-spam.
_drift_warnings_emitted = 0
_MAX_DRIFT_WARNINGS = 10


def _show_schema_drift(exc: audit_schema.InvalidAuditEvent) -> None:
    """Bound repeated schema-drift notices in the terminal renderer."""
    global _drift_warnings_emitted
    if _drift_warnings_emitted < _MAX_DRIFT_WARNINGS:
        _drift_warnings_emitted += 1
        console.print(f"[dim yellow]schema drift: {exc}[/dim yellow]")
        if _drift_warnings_emitted == _MAX_DRIFT_WARNINGS:
            console.print("[dim yellow]further schema-drift warnings suppressed[/dim yellow]")


_audit_line_parser = None


def _get_audit_line_parser():
    """Create the command-only parser without loading Pydantic at CLI import."""
    global _audit_line_parser
    if _audit_line_parser is None:
        _audit_line_parser = audit_stream.AuditLineParser(
            on_schema_drift=_show_schema_drift,
            seen_event_ids=2048,
        )
    return _audit_line_parser


def _reset_audit_line_parser() -> None:
    """Discard parser state before an independent watch run or test."""
    global _audit_line_parser
    _audit_line_parser = None


def _parse_jsonl_line(line: str) -> dict | None:
    """Parse one audit line with the shared reader used by operator clients."""
    return _get_audit_line_parser().parse(line)


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
    """Tail audit JSONL using the UI-independent stream reader."""

    def show_status(status: str) -> None:
        if status.startswith("waiting:"):
            console.print(f"[dim]Waiting for log file: {path}[/dim]")
        elif status == "removed":
            console.print("[dim]Log file removed, waiting...[/dim]")
        elif status == "rotated":
            console.print("[dim]Log rotated, reopening...[/dim]")
        elif status == "truncated":
            console.print("[dim]Log truncated, reopening...[/dim]")

    yield from audit_stream.follow_jsonl(
        path,
        parse_line=_parse_jsonl_line,
        follow=follow,
        tick_interval=tick_interval,
        on_status=show_status,
    )


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

    approve: Callable[[dict, admin_api.AdminAPI], str | dict | None]
    deny: Callable[[dict, admin_api.AdminAPI], None]
    format_row: Callable[[dict], tuple[str, str, str, str]]  # agent, action, risk, description
    format_detail: Callable[[dict], Panel]  # full panel for review mode


def _credential_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
    return operator_approvals.approve(event, api)


def _credential_deny(event: dict, api: admin_api.AdminAPI) -> None:
    operator_approvals.deny(event, api)


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


def _gateway_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
    return operator_approvals.approve(event, api)


def _gateway_deny(event: dict, api: admin_api.AdminAPI) -> None:
    operator_approvals.deny(event, api)


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


def _service_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
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
            event = {
                **event,
                "approval": {
                    **approval,
                    "scope_hint": {**scope, "capability": capability},
                },
            }

        # Credential flow: pick existing or create new
        cred_name = _pick_or_create_credential(service)
        if not cred_name:
            raise NotImplementedError("Credential required")

    except (KeyboardInterrupt, EOFError):
        raise NotImplementedError("Interrupted")

    return operator_approvals.approve(
        event,
        api,
        service_credential=cred_name,
    )


def _pick_or_create_credential(service: str) -> str | None:
    """Interactive credential selection: pick existing or create new.

    Returns credential name, or None if cancelled.
    """
    from ._service_discovery import ServiceDiscoveryError, find_service
    from .vault import _load_vault

    try:
        vault, VaultCredential = _load_vault()
    except (OSError, ValueError) as e:
        console.print(f"[red]Error loading vault:[/red] {e}")
        return None

    # Look up auth type from service definition
    try:
        svc = find_service(service)
    except ServiceDiscoveryError as error:
        console.print(f"[red]Service definitions failed to load:[/red] {escape(str(error))}")
        return None
    if svc is None:
        console.print(
            f"[red]Service '{escape(service)}' is not available in the effective registry.[/red]"
        )
        return None
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


def _service_deny(event: dict, api: admin_api.AdminAPI) -> None:
    operator_approvals.deny(event, api)


def _unsupported_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
    raise NotImplementedError(
        f"Cannot approve unknown approval_type {event.get('approval', {}).get('approval_type')!r} "
        "in batch mode — use individual review (r<N>) instead"
    )


def _unsupported_deny(event: dict, api: admin_api.AdminAPI) -> None:
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


# ---------------------------------------------------------------------------
# Network egress approval handlers
# ---------------------------------------------------------------------------

# Duration options: label → timedelta (None = permanent)
DURATION_OPTIONS = {
    "1h": timedelta(hours=1),
    "8h": timedelta(hours=8),
    "1d": timedelta(days=1),
    "7d": timedelta(days=7),
}


def _parse_duration(code: str) -> str | None:
    """Parse duration code (1h/8h/1d/7d) to ISO expires string, or None for permanent."""
    td = DURATION_OPTIONS.get(code)
    if td is None:
        return None
    return (datetime.now(UTC) + td).isoformat()


def _host_to_domain(host: str) -> str:
    """Convert api.stripe.com → *.stripe.com for domain scope."""
    parts = host.split(".")
    if len(parts) > 2:
        return "*." + ".".join(parts[1:])
    return "*." + host


def _network_egress_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
    """Approve with defaults — used by batch approve and fallback."""
    return operator_approvals.approve(event, api)


def _network_egress_deny(event: dict, api: admin_api.AdminAPI) -> None:
    """Deny with defaults — used by batch deny and fallback."""
    operator_approvals.deny(event, api)


def _prompt_egress_approval(item: BatchItem, api: admin_api.AdminAPI) -> bool:
    """Interactive prompt for network egress approval.

    Single prompt following the existing a/d/l pattern. Scope modifiers
    can be appended: domain scope (D suffix), duration (1h/8h/1d/7d suffix),
    all-agents (A suffix).

    Input examples:
        a       → approve, host scope, this agent, permanent
        d       → deny, host scope, this agent, 1d
        a7d     → approve, host scope, this agent, 7 days
        aD      → approve, domain scope, this agent, permanent
        dDA     → deny, domain scope, all agents, 1d
        l       → defer

    Returns True if approved.
    """
    dispatch = DISPATCH["network_egress"]
    event = item.event
    approval = event.get("approval", {})
    host = event.get("host", approval.get("target", "unknown"))
    agent_name = event.get("agent")

    # Show detail panel
    console.print()
    console.print(dispatch.format_detail(event))

    # Single prompt
    while True:
        try:
            response = console.input(
                "[bold]Action ([green]a[/green]/[red]d[/red]/[dim]l[/dim]): [/bold]"
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Interrupted[/dim]")
            return False

        if response.lower() in ("l", "later", ""):
            console.print("[dim]Deferred[/dim]")
            return False

        # Parse: first char is action, rest are modifiers
        raw = response.lower()
        if raw[0] in ("a", "y"):
            action = "approve"
            mods = raw[1:]
        elif raw[0] in ("d", "n"):
            action = "deny"
            mods = raw[1:]
        else:
            console.print("[dim]Use: a(pprove), d(eny), l(ater). Modifiers: D=domain, A=all-agents, 1h/8h/1d/7d=duration[/dim]")
            continue

        # Parse modifiers
        use_domain = "d" in mods.replace("1d", "").replace("7d", "").replace("8d", "")  # D for domain, not duration
        use_all_agents = "a" in mods[0:] if action == "deny" else "a" in mods  # avoid 'a' from action
        duration = None
        for dur_key in ("8h", "1h", "7d", "1d"):
            if dur_key in mods:
                duration = dur_key
                break

        # Apply defaults
        if action == "deny" and duration is None:
            duration = "1d"

        target = _host_to_domain(host) if use_domain else host
        apply_to_agent = None if use_all_agents else (agent_name if agent_name and agent_name != "unknown" else None)
        expires = _parse_duration(duration) if duration else None

        # Execute
        try:
            if action == "approve":
                api.allow_host(host=target, rate=600, agent=apply_to_agent)
                scope_label = f"[bold]{escape(target)}[/bold]"
                if apply_to_agent:
                    scope_label += f" (agent: {escape(apply_to_agent)})"
                dur_label = f"expires {duration}" if duration else "permanent"
                console.print(f"[green]Approved[/green] {scope_label} [{dur_label}]")
                return True
            else:
                api.deny_host(host=target, expires=expires, agent=apply_to_agent)
                scope_label = f"[bold]{escape(target)}[/bold]"
                if apply_to_agent:
                    scope_label += f" (agent: {escape(apply_to_agent)})"
                dur_label = f"expires {duration}" if duration else "permanent"
                console.print(f"[red]Denied[/red] {scope_label} [{dur_label}]")
                return False
        except (admin_api.APIError, NotImplementedError) as e:
            console.print(f"[red]Error:[/red] {escape(str(e))}")
            return False


def _network_egress_format_row(event: dict) -> tuple[str, str, str, str]:
    approval = event.get("approval", {})
    agent = event.get("agent", "\u2014")
    host = event.get("host", approval.get("target", "unknown"))
    action = f"egress \u2192 {host}"
    risk = "network access"
    description = event.get("summary", "")
    return (agent, action, risk, description)


def _network_egress_format_detail(event: dict) -> Panel:
    from rich.table import Table

    approval = event.get("approval", {})
    details = event.get("details", {})

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")

    host = event.get("host", approval.get("target", "unknown"))
    agent = event.get("agent", "\u2014")
    table.add_row("Destination", f"[bold]{host}[/bold]")
    table.add_row("Agent", agent)
    table.add_row("Type", "Network egress approval")
    if details.get("decision_type"):
        table.add_row("Decision", details["decision_type"])
    ts = event.get("ts", "")
    if ts:
        table.add_row("Time", str(ts))

    return Panel(table, title="[bold]Egress Approval[/bold]", border_style="yellow")


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


def _contract_binding_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
    return operator_approvals.approve(event, api)


def _contract_binding_deny(event: dict, api: admin_api.AdminAPI) -> None:
    operator_approvals.deny(event, api)



def _dedup_key_from_approval(event: dict) -> str:
    """Derive dedup key from the approval field on an event."""
    return audit_stream.approval_dedup_key(event)


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
    api: admin_api.AdminAPI,
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


def _prompt_single_item(item: BatchItem, api: admin_api.AdminAPI) -> bool:
    """Prompt for a single item using the appropriate per-type handler.

    Returns True if approved.
    """
    dispatch = DISPATCH.get(item.approval_type, FALLBACK_DISPATCH)

    if item.approval_type == "gateway_route":
        return handle_risky_route_approval(item.event, api)
    elif item.approval_type == "credential":
        return handle_approval(item.event, api)
    elif item.approval_type == "network_egress":
        return _prompt_egress_approval(item, api)
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
                except (admin_api.APIError, NotImplementedError) as e:
                    console.print(f"[red]Error:[/red] {escape(str(e))}")
                    return False
            elif response in ("d", "deny", "n", "no"):
                try:
                    dispatch.deny(item.event, api)
                except (admin_api.APIError, NotImplementedError) as e:
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
                except (admin_api.APIError, NotImplementedError) as e:
                    console.print(f"[red]Error:[/red] {escape(str(e))}")
                    return False
            elif response in ("d", "deny", "n", "no"):
                try:
                    dispatch.deny(item.event, api)
                except (admin_api.APIError, NotImplementedError) as e:
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
    api: admin_api.AdminAPI,
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
        except (admin_api.APIError, NotImplementedError) as e:
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
                    except (admin_api.APIError, NotImplementedError) as e:
                        console.print(f"[red]Error:[/red] {escape(str(e))}")
                    break
                elif response.lower() in ("d", "deny", "n", "no"):
                    try:
                        dispatch.deny(item.event, api)
                        stats.mark_resolved(item.dedup_key)
                    except (admin_api.APIError, NotImplementedError) as e:
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
    api: admin_api.AdminAPI,
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
        except (admin_api.APIError, NotImplementedError) as e:
            console.print(f"[red]Error denying #{item.index}:[/red] {escape(str(e))}")
    console.print(f"[red]Denied {denied_count} item(s)[/red]")


def _batch_select(
    items: list[BatchItem],
    indices: list[int],
    api: admin_api.AdminAPI,
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
    return audit_stream.resolved_approval_key(event)


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

    def show_error(exc: Exception) -> None:
        console.print(f"[yellow]Warning:[/yellow] Failed to scan log for pending approvals: {escape(str(exc))}")

    return audit_stream.scan_pending_approvals(log_path, on_error=show_error)


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


def _plumb_approve(event: dict, api: admin_api.AdminAPI) -> str | None:
    """Approve a plumb agent-to-agent chat request -> creates a grant."""
    return operator_approvals.approve(event, api)


def _plumb_deny(event: dict, api: admin_api.AdminAPI) -> None:
    """Deny a plumb chat request."""
    operator_approvals.deny(event, api)


def _plumb_format_row(event: dict) -> tuple[str, str, str, str]:
    approval = event.get("approval", {})
    hint = approval.get("scope_hint", {})
    agent = event.get("agent", hint.get("requester", "—"))
    targets = [p for p in hint.get("participants", []) if p != agent]
    action = f"chat → {', '.join(targets) or approval.get('target', '?')}"
    return (agent, action, "agent-to-agent", event.get("summary", ""))


def _plumb_format_detail(event: dict) -> Panel:
    from rich.table import Table

    approval = event.get("approval", {})
    hint = approval.get("scope_hint", {})
    requester = hint.get("requester", event.get("agent", "—"))
    participants = hint.get("participants", [])
    ttl = hint.get("ttl_seconds", "?")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="dim")
    table.add_column("Value")
    # Trusted, system-derived fields (attribution) — safe to render as structure.
    table.add_row("Requester", f"[bold]{escape(str(requester))}[/bold]")
    table.add_row("Participants", escape(", ".join(str(p) for p in participants)))
    table.add_row("TTL", f"{ttl}s")
    ts = event.get("ts", "")
    if ts:
        table.add_row("Time", str(ts))
    # Agent-authored prose is untrusted. PlumbService stores it sanitized but
    # untruncated; watch applies a display cap and escape() neutralizes rich
    # markup so it can't spoof the operator prompt.
    from safeyolo.core.plumb_service import UNTRUSTED_FIELD_DISPLAY_MAXLEN

    topic = audit_schema.sanitize_for_log(hint.get("topic", ""), max_len=UNTRUSTED_FIELD_DISPLAY_MAXLEN)
    note = audit_schema.sanitize_for_log(hint.get("note", ""), max_len=UNTRUSTED_FIELD_DISPLAY_MAXLEN)
    if topic or note:
        table.add_row("", "")
        table.add_row("[yellow]agent-supplied (untrusted)[/yellow]", "")
        if topic:
            table.add_row("  topic", escape(str(topic)))
        if note:
            table.add_row("  note", escape(str(note)))

    return Panel(
        table,
        title="[bold]Agent Chat Request (plumb)[/bold]",
        border_style="magenta",
    )


def _desktop_present_approve(event: dict, api: admin_api.AdminAPI) -> dict:
    result = operator_approvals.approve(event, api)
    if not isinstance(result, dict):
        raise NotImplementedError("Desktop presentation returned an invalid result")
    return result


def _desktop_present_deny(event: dict, api: admin_api.AdminAPI) -> None:
    operator_approvals.deny(event, api)


def _desktop_present_format_row(event: dict) -> tuple[str, str, str, str]:
    agent = event.get("agent", "—")
    target = event.get("approval", {}).get("target", "?")
    return (agent, "present desktop", "desktop access", target)


def _desktop_present_format_detail(event: dict) -> Panel:
    approval = event.get("approval", {})
    scope = approval.get("scope_hint", {})
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Key", style="dim")
    table.add_column("Value")
    table.add_row("Agent", escape(str(event.get("agent", "unknown"))))
    table.add_row("Agent ID", escape(str(scope.get("agent_id", "unknown"))))
    table.add_row("Action", "Start or reuse a local desktop preview")
    return Panel(
        table,
        title="[bold]Desktop Presentation Request[/bold]",
        subtitle="[green][A]pprove[/green] · [red][D]eny[/red] · [dim][L]ater[/dim]",
        border_style="yellow",
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
    "network_egress": ApprovalDispatch(
        approve=_network_egress_approve,
        deny=_network_egress_deny,
        format_row=_network_egress_format_row,
        format_detail=_network_egress_format_detail,
    ),
    "plumb": ApprovalDispatch(
        approve=_plumb_approve,
        deny=_plumb_deny,
        format_row=_plumb_format_row,
        format_detail=_plumb_format_detail,
    ),
    "desktop_present": ApprovalDispatch(
        approve=_desktop_present_approve,
        deny=_desktop_present_deny,
        format_row=_desktop_present_format_row,
        format_detail=_desktop_present_format_detail,
    ),
}


# ---------------------------------------------------------------------------
# Action dispatch — non-approval event actions (Phase 2)
# ---------------------------------------------------------------------------


@dataclass
class ActionDef:
    """A single action available on a non-approval event."""

    key: str  # single char shortcut
    label: str  # for hint display
    confirm: str  # "instant" | "value" | "explicit"
    execute: Callable[[dict, admin_api.AdminAPI], str]  # returns status message
    value_prompt: str | None = None
    value_default: Callable[[dict], str] | None = None


@dataclass
class ActionDispatch:
    """Maps non-approval events to available actions."""

    match: Callable[[dict], bool]  # event matcher
    actions: list[ActionDef]  # available actions
    format_hint: Callable[[dict], str]  # inline hint string


def _match_budget_exceeded(event: dict) -> bool:
    return event.get("event") == "security.network_guard" and event.get("decision") == "budget_exceeded"


def _match_access_denied(event: dict) -> bool:
    return event.get("event") == "security.network_guard" and event.get("decision") == "deny"


def _match_circuit_open(event: dict) -> bool:
    return event.get("event") == "ops.circuit_breaker.open"


def _match_pattern_block(event: dict) -> bool:
    return event.get("event") == "security.pattern_scanner" and event.get("decision") == "deny"


def _exec_bump_rate(event: dict, api: admin_api.AdminAPI, value: str | None = None) -> str:
    host = event.get("host", "")
    details = event.get("details", {})
    old_rate = details.get("budget", details.get("rate", 0))
    new_rate = int(value) if value else old_rate * 2
    result = api.update_host_rate(host=host, rate=new_rate)
    return f"Rate limit: {result.get('old_rate')} \u2192 {result.get('new_rate')}"


def _exec_reset_budget(event: dict, api: admin_api.AdminAPI) -> str:
    host = event.get("host", "")
    resource = f"network:request:{host}"
    api.reset_budget(resource=resource)
    return f"Budget reset for {host}"


def _exec_allow_host(event: dict, api: admin_api.AdminAPI) -> str:
    host = event.get("host", "")
    result = api.allow_host(host=host, rate=600)
    return f"Host allowed: {result.get('host')} (rate={result.get('rate')})"


def _exec_reset_circuit(event: dict, api: admin_api.AdminAPI) -> str:
    host = event.get("host", "")
    api.reset_circuit(host=host)
    return f"Circuit reset for {host}"


def _exec_suppress_pattern(event: dict, api: admin_api.AdminAPI) -> str:
    host = event.get("host", "")
    api.add_host_bypass(host=host, addon="pattern-scanner")
    return f"Pattern scanner bypassed for {host}"


def _default_bump_rate(event: dict) -> str:
    details = event.get("details", {})
    rate = details.get("budget", details.get("rate", 0))
    return str(rate * 2) if rate else "6000"


def _hint_budget_exceeded(event: dict) -> str:
    return r"\[b=bump rate, r=reset]"


def _hint_access_denied(event: dict) -> str:
    return r"\[h=allow host]"


def _hint_circuit_open(event: dict) -> str:
    return r"\[x=reset circuit]"


def _hint_pattern_block(event: dict) -> str:
    return r"\[s=suppress pattern]"


ACTION_DISPATCH: list[ActionDispatch] = [
    ActionDispatch(
        match=_match_budget_exceeded,
        actions=[
            ActionDef(
                key="b",
                label="bump rate",
                confirm="value",
                execute=lambda e, api: "",  # placeholder — value flow handles this
                value_prompt="New rate limit (req/min)",
                value_default=_default_bump_rate,
            ),
            ActionDef(
                key="r",
                label="reset budget",
                confirm="instant",
                execute=_exec_reset_budget,
            ),
        ],
        format_hint=_hint_budget_exceeded,
    ),
    ActionDispatch(
        match=_match_access_denied,
        actions=[
            ActionDef(
                key="h",
                label="allow host",
                confirm="explicit",
                execute=_exec_allow_host,
            ),
        ],
        format_hint=_hint_access_denied,
    ),
    ActionDispatch(
        match=_match_circuit_open,
        actions=[
            ActionDef(
                key="x",
                label="reset circuit",
                confirm="instant",
                execute=_exec_reset_circuit,
            ),
        ],
        format_hint=_hint_circuit_open,
    ),
    ActionDispatch(
        match=_match_pattern_block,
        actions=[
            ActionDef(
                key="s",
                label="suppress pattern",
                confirm="explicit",
                execute=_exec_suppress_pattern,
            ),
        ],
        format_hint=_hint_pattern_block,
    ),
]


def find_action_dispatch(event: dict) -> ActionDispatch | None:
    """Find matching ActionDispatch for an event, if any."""
    for dispatch in ACTION_DISPATCH:
        if dispatch.match(event):
            return dispatch
    return None


def build_action_map(event: dict, dispatch: ActionDispatch) -> dict[str, tuple[dict, ActionDef]]:
    """Build a key -> (event, action_def) map for the matched dispatch."""
    return {action.key: (event, action) for action in dispatch.actions}


def format_action_help() -> str:
    """Format help text listing all action keys."""
    lines = ["[bold]Action keys (active on last non-approval event):[/bold]", ""]
    for dispatch in ACTION_DISPATCH:
        for action in dispatch.actions:
            confirm_tag = {"instant": "instant", "value": "input required", "explicit": "confirm y/N"}[action.confirm]
            lines.append(f"  [bold]{action.key}[/bold]  {action.label}  [dim]({confirm_tag})[/dim]")
    lines.append("")
    lines.append("  [bold]?[/bold]  show this help")
    return "\n".join(lines)


def handle_action_key(
    key: str,
    last_actionable: dict[str, tuple[dict, ActionDef]],
    api: admin_api.AdminAPI,
) -> bool:
    """Handle an action key press. Returns True if handled."""
    if key == "?":
        console.print(format_action_help())
        return True

    if key not in last_actionable:
        return False

    event, action_def = last_actionable[key]
    host = event.get("host", "")

    try:
        if action_def.confirm == "instant":
            result_msg = action_def.execute(event, api)
            console.print(f"  [green]\u2713[/green] {result_msg}")

        elif action_def.confirm == "value":
            default = action_def.value_default(event) if action_def.value_default else ""
            prompt_text = f"  {action_def.value_prompt} for {host}"
            if default:
                prompt_text += f" [{default}]"
            prompt_text += ": "
            try:
                raw_value = console.input(prompt_text).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Cancelled[/dim]")
                return True
            value = raw_value or default
            if not value:
                console.print("  [dim]No value provided — cancelled[/dim]")
                return True
            # For bump rate, use the dedicated executor
            if action_def.key == "b":
                result_msg = _exec_bump_rate(event, api, value=value)
            else:
                result_msg = action_def.execute(event, api)
            console.print(f"  [green]\u2713[/green] {result_msg}")

        elif action_def.confirm == "explicit":
            try:
                confirm = console.input(f"  {action_def.label.title()} {host}? (y/N): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                console.print("\n  [dim]Cancelled[/dim]")
                return True
            if confirm != "y":
                console.print("  [dim]Cancelled[/dim]")
                return True
            result_msg = action_def.execute(event, api)
            console.print(f"  [green]\u2713[/green] {result_msg}")

    except admin_api.APIError as e:
        console.print(f"  [red]Error:[/red] {escape(str(e))}")
    except Exception as e:
        console.print(f"  [red]Error:[/red] {escape(str(e))}")

    return True


def handle_risky_route_approval(event: dict, api: admin_api.AdminAPI) -> bool:
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
                except admin_api.APIError as e:
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
                except admin_api.APIError as e:
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
        except admin_api.APIError as e:
            console.print(f"[red]API Error:[/red] {e}")
            return False


def handle_approval(event: dict, api: admin_api.AdminAPI) -> bool:
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
            except admin_api.APIError as e:
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
            except admin_api.APIError as e:
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
            api = admin_api.get_api()
            # Test connection
            api.health()
        except admin_api.APIError as e:
            console.print(f"[yellow]Warning:[/yellow] Cannot connect to admin API: {e}")
            console.print("[dim]Approvals will be disabled. Run 'safeyolo start' first.[/dim]")
            api = None

    console.print(f"[bold]Watching:[/bold] {log_path}")
    if interactive and api:
        console.print("[dim]Press Ctrl+C to exit. Approvals and policy actions will appear inline.[/dim]")
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

    # Action dispatch state: tracks the last actionable event's available keys
    last_actionable: dict[str, tuple[dict, ActionDef]] = {}
    show_action_hints = interactive and api is not None
    # Deadline for prompting after actionable events settle
    action_deadline: float | None = None
    action_suppressed: int = 0  # count of suppressed duplicate actionable events
    action_dedup_key: str = ""  # host:event dedup key for current actionable batch
    ACTION_SETTLE_WINDOW = 1.0  # seconds to wait for more events before prompting

    def _flush_actions() -> None:
        """Prompt for action on the last actionable event."""
        nonlocal last_actionable, action_deadline, action_suppressed, action_dedup_key
        if not last_actionable or not api:
            action_deadline = None
            action_suppressed = 0
            action_dedup_key = ""
            return
        action_deadline = None
        if action_suppressed > 0:
            console.print(f"  [dim]({action_suppressed} more identical event(s) suppressed)[/dim]")
        action_suppressed = 0
        action_dedup_key = ""
        # Build hint string from available keys
        keys_display = "  ".join(
            f"[bold]{k}[/bold]={escape(adef.label)}" for k, (_, adef) in last_actionable.items()
        )
        try:
            raw = console.input(
                f"  [dim]Action ({keys_display}  [bold]?[/bold]=help  Enter=skip):[/dim] "
            ).strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print()
            last_actionable = {}
            return
        if raw:
            handle_action_key(raw, last_actionable, api)
        last_actionable = {}

    try:
        for event in tail_jsonl(log_path, follow=follow, tick_interval=0.5):
            # Tick event (None) — check deadlines
            if event is None:
                if batch_deadline is not None and time.time() >= batch_deadline:
                    _flush_batch()
                if action_deadline is not None and time.time() >= action_deadline:
                    _flush_actions()
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
                # Flush any pending action prompt before showing approval batch
                if action_deadline is not None:
                    _flush_actions()
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
                # Other events - show summary with action hints
                # Suppress duplicate actionable events (e.g., 100 rate limit hits)
                event_dedup = f"{event.get('host', '')}:{event.get('event', '')}"
                if show_action_hints and event_dedup == action_dedup_key and last_actionable:
                    action_suppressed += 1
                    action_deadline = time.time() + ACTION_SETTLE_WINDOW
                else:
                    # Flush previous action batch if a different event arrives
                    if action_deadline is not None:
                        _flush_actions()
                    matched = _print_event_summary(event, show_hints=show_action_hints)
                    if matched:
                        last_actionable = build_action_map(event, matched)
                        action_dedup_key = event_dedup
                        action_suppressed = 0
                        action_deadline = time.time() + ACTION_SETTLE_WINDOW
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


def _print_event_summary(event: dict, show_hints: bool = False) -> ActionDispatch | None:
    """Print a one-line summary of an event.

    Args:
        event: The event dict
        show_hints: If True, append action hints for actionable events

    Returns:
        The matched ActionDispatch if the event is actionable, else None
    """
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

    # Check for actionable event
    matched_dispatch = None
    hint_str = ""
    if show_hints:
        matched_dispatch = find_action_dispatch(event)
        if matched_dispatch:
            hint_str = f"  [bold cyan]{matched_dispatch.format_hint(event)}[/bold cyan]"

    console.print(f"[dim]{timestamp_str}[/dim] [{style}]{event_type}[/{style}] {agent_prefix}{escape(summary)}{hint_str}")
    return matched_dispatch
