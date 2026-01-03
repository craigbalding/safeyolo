#!/usr/bin/env python3
"""
logtail.py - Live tail of SafeYolo JSONL logs with summaries

Shows warnings/blocks immediately, prints periodic traffic summaries.
Optionally displays a Rich-based live dashboard.

Usage:
    # Tail docker logs
    docker logs -f safeyolo 2>&1 | python contrib/monitors/logtail.py

    # Tail a log file
    tail -f logs/safeyolo.jsonl | python contrib/monitors/logtail.py

    # From file with visual mode
    python contrib/monitors/logtail.py --visual logs/safeyolo.jsonl

    # Custom summary interval
    python contrib/monitors/logtail.py --interval 10

Requires: pip install rich (optional, for --visual mode)
"""

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import TextIO

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


@dataclass
class WindowStats:
    """Statistics for a time window."""

    requests: int = 0
    by_domain: dict = field(default_factory=lambda: defaultdict(int))
    by_status: dict = field(default_factory=lambda: defaultdict(int))
    latencies: list = field(default_factory=list)
    blocks: int = 0
    warnings: int = 0

    def add_request(self, domain: str, status: int, latency_ms: float = None):
        self.requests += 1
        self.by_domain[domain] += 1
        if status:
            bucket = f"{status // 100}xx"
            self.by_status[bucket] += 1
        if latency_ms is not None:
            self.latencies.append(latency_ms)

    def avg_latency(self) -> float:
        return sum(self.latencies) / len(self.latencies) if self.latencies else 0

    def max_latency(self) -> float:
        return max(self.latencies) if self.latencies else 0

    def p95_latency(self) -> float:
        if not self.latencies:
            return 0
        sorted_lat = sorted(self.latencies)
        idx = int(len(sorted_lat) * 0.95)
        return sorted_lat[min(idx, len(sorted_lat) - 1)]

    def top_domains(self, n: int = 3) -> list:
        return sorted(self.by_domain.items(), key=lambda x: -x[1])[:n]


def format_ts(ts_str: str) -> str:
    """Format ISO timestamp to HH:MM:SS."""
    try:
        if "T" in ts_str:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        pass
    return ts_str[:8] if ts_str else "??:??:??"


def print_block(entry: dict):
    """Print a block event prominently."""
    ts = format_ts(entry.get("ts", ""))
    blocker = entry.get("blocked_by", entry.get("addon", "unknown"))
    host = entry.get("host", entry.get("domain", "?"))
    path = entry.get("path", "")
    reason = entry.get("reason", entry.get("rule", ""))
    fingerprint = entry.get("credential_fingerprint", entry.get("token_hmac", ""))

    print(
        f"{RED}{BOLD}[BLOCK]{RESET} {DIM}{ts}{RESET} {RED}{blocker}{RESET} "
        f"blocked {CYAN}{host}{path}{RESET}",
        file=sys.stderr,
    )
    if reason:
        print(f"        {DIM}reason:{RESET} {reason}", file=sys.stderr)
    if fingerprint:
        print(f"        {DIM}fingerprint:{RESET} {fingerprint[:20]}...", file=sys.stderr)


def print_security_event(entry: dict, event_type: str):
    """Print a security event."""
    ts = format_ts(entry.get("ts", ""))
    host = entry.get("host", entry.get("domain", "?"))
    decision = entry.get("decision", "warn")
    path = entry.get("path", "")

    if event_type == "security.ratelimit":
        wait_ms = entry.get("wait_ms", 0)
        color = RED if decision == "block" else YELLOW
        print(
            f"{color}[RATE]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} "
            f"{decision} {DIM}(wait {wait_ms:.0f}ms){RESET}",
            file=sys.stderr,
        )

    elif event_type == "security.circuit":
        circuit_event = entry.get("circuit_event", "unknown")
        domain = entry.get("domain", host)
        colors = {"block": RED, "open": YELLOW, "reopen": YELLOW, "half_open": GREEN, "close": GREEN}
        color = colors.get(circuit_event, YELLOW)
        print(
            f"{color}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{domain}{RESET} {circuit_event}",
            file=sys.stderr,
        )

    elif event_type == "security.credential":
        rule = entry.get("rule", "")
        fingerprint = entry.get("credential_fingerprint", entry.get("token_hmac", ""))[:16]
        reason = entry.get("reason", "")
        color = RED if decision == "block" else (YELLOW if decision == "warn" else GREEN)
        label = "CRED" if decision != "allow" else "CRED-OK"
        print(
            f"{color}[{label}]{RESET} {DIM}{ts}{RESET} {rule} -> {CYAN}{host}{path}{RESET} "
            f"{DIM}[{decision}]{RESET}",
            file=sys.stderr,
        )
        if reason:
            print(f"        {DIM}reason:{RESET} {reason} {DIM}fp:{fingerprint}{RESET}", file=sys.stderr)

    elif event_type == "security.pattern":
        rule_id = entry.get("rule_id", entry.get("rule", "?"))
        rule_name = entry.get("rule_name", "")
        color = RED if decision == "block" else (GREEN if decision == "redact" else YELLOW)
        name_part = f" ({rule_name})" if rule_name else ""
        print(
            f"{color}[PATTERN]{RESET} {DIM}{ts}{RESET} {rule_id}{name_part} -> "
            f"{CYAN}{host}{RESET} {DIM}[{decision}]{RESET}",
            file=sys.stderr,
        )

    elif event_type == "security.injection":
        classification = entry.get("classification", "?")
        confidence = entry.get("confidence", 0)
        model = entry.get("model", "")
        latency = entry.get("latency_ms", 0)
        color = RED if decision == "block" else YELLOW
        model_part = f" {DIM}{model} {latency:.0f}ms{RESET}" if model else ""
        print(
            f"{color}[INJECT]{RESET} {DIM}{ts}{RESET} {RED}{classification}{RESET} "
            f"({confidence:.0%}) -> {CYAN}{host}{RESET}{model_part} {DIM}[{decision}]{RESET}",
            file=sys.stderr,
        )
        text_preview = entry.get("text_preview", "")
        if text_preview:
            preview = text_preview[:80].replace("\n", " ")
            if len(text_preview) > 80:
                preview += "..."
            print(f"        {DIM}text:{RESET} {preview}", file=sys.stderr)

    elif event_type == "security.yara":
        rules = entry.get("rules", [])
        rules_str = ", ".join(rules) if isinstance(rules, list) else str(rules)
        color = RED if decision == "block" else YELLOW
        print(
            f"{color}[YARA]{RESET} {DIM}{ts}{RESET} {rules_str} -> "
            f"{CYAN}{host}{RESET} {DIM}[{decision}]{RESET}",
            file=sys.stderr,
        )

    else:
        # Generic security event
        print(
            f"{YELLOW}[SECURITY]{RESET} {DIM}{ts}{RESET} {event_type} {CYAN}{host}{RESET}",
            file=sys.stderr,
        )


def print_admin_event(entry: dict, event_type: str):
    """Print an admin event."""
    ts = format_ts(entry.get("ts", ""))
    client_ip = entry.get("client_ip", "?")

    if event_type == "admin.approval_added":
        token = entry.get("token_hmac", entry.get("token", "?"))[:8]
        project = entry.get("project", "default")
        print(
            f"{GREEN}[ADMIN]{RESET} {DIM}{ts}{RESET} approval added {token}... "
            f"{DIM}project={project} from={client_ip}{RESET}",
            file=sys.stderr,
        )

    elif event_type == "admin.policy_write":
        project = entry.get("project", "?")
        print(
            f"{GREEN}[ADMIN]{RESET} {DIM}{ts}{RESET} policy written "
            f"{DIM}project={project} from={client_ip}{RESET}",
            file=sys.stderr,
        )

    elif event_type == "admin.mode_change":
        target = entry.get("target_addon", entry.get("addon", "?"))
        new_mode = entry.get("new_mode", "?")
        color = RED if new_mode == "block" else GREEN
        print(
            f"{color}[ADMIN]{RESET} {DIM}{ts}{RESET} mode_change {target} -> {new_mode} "
            f"{DIM}from={client_ip}{RESET}",
            file=sys.stderr,
        )

    elif event_type == "admin.auth_failure":
        path = entry.get("path", "?")
        print(
            f"{RED}[ADMIN]{RESET} {DIM}{ts}{RESET} auth_failure {path} "
            f"{DIM}from={client_ip}{RESET}",
            file=sys.stderr,
        )

    else:
        print(f"{CYAN}[ADMIN]{RESET} {DIM}{ts}{RESET} {event_type}", file=sys.stderr)


def print_ops_event(entry: dict, event_type: str):
    """Print an ops event."""
    ts = format_ts(entry.get("ts", ""))
    addon = entry.get("addon", "?")
    print(f"{CYAN}[OPS]{RESET} {DIM}{ts}{RESET} {event_type} {DIM}addon={addon}{RESET}", file=sys.stderr)


def print_summary(stats: WindowStats, window_secs: float):
    """Print a compact summary line."""
    if stats.requests == 0:
        return

    rps = stats.requests / window_secs if window_secs > 0 else 0

    # Status breakdown
    status_parts = []
    for bucket in ["2xx", "3xx", "4xx", "5xx"]:
        count = stats.by_status.get(bucket, 0)
        if count > 0:
            color = GREEN if bucket == "2xx" else (YELLOW if bucket in ("3xx", "4xx") else RED)
            status_parts.append(f"{color}{count}{RESET}")
    status_str = "/".join(status_parts) if status_parts else "-"

    # Top domains
    top = stats.top_domains(3)
    domains_str = " ".join(f"{d}:{c}" for d, c in top)

    # Latency
    avg_lat = stats.avg_latency()
    p95_lat = stats.p95_latency()
    lat_str = f"{avg_lat:.0f}ms" if avg_lat else "-"
    if p95_lat > avg_lat * 1.5 and p95_lat > 100:
        lat_str += f" {DIM}(p95 {p95_lat:.0f}){RESET}"

    # Blocks/warnings indicator
    alert_str = ""
    if stats.blocks > 0:
        alert_str += f" {RED}{stats.blocks} blocked{RESET}"
    if stats.warnings > 0:
        alert_str += f" {YELLOW}{stats.warnings} warn{RESET}"

    now = datetime.now().strftime("%H:%M:%S")
    print(
        f"{DIM}[{now}]{RESET} {stats.requests} req ({rps:.1f}/s) {status_str} "
        f"lat={lat_str} {DIM}{domains_str}{RESET}{alert_str}",
        file=sys.stderr,
    )


def process_entry(entry: dict, stats: WindowStats) -> bool:
    """Process a log entry. Returns True if it was a notable event."""
    event = entry.get("event", "")
    decision = entry.get("decision", "")

    # Blocked requests
    if entry.get("blocked_by") or decision == "block":
        print_block(entry)
        stats.blocks += 1
        return True

    # Security events
    if event.startswith("security."):
        print_security_event(entry, event)
        if decision == "warn":
            stats.warnings += 1
        return True

    # Admin events
    if event.startswith("admin."):
        print_admin_event(entry, event)
        return True

    # Ops events
    if event.startswith("ops."):
        print_ops_event(entry, event)
        return True

    # Traffic events - collect stats
    if event in ("traffic.request", "traffic.response"):
        host = entry.get("host", "")
        status = entry.get("status", 0)
        latency = entry.get("latency_ms", entry.get("ms"))
        if host:
            stats.add_request(host, status, latency)

    return False


def parse_line(line: str) -> dict | None:
    """Parse a log line, handling docker log prefixes."""
    line = line.strip()
    if not line:
        return None

    try:
        return json.loads(line)
    except json.JSONDecodeError:
        # Try extracting JSON from docker log format
        if "{" in line:
            json_start = line.index("{")
            try:
                return json.loads(line[json_start:])
            except json.JSONDecodeError:
                pass
    return None


def run_visual_mode(source: TextIO, interval: float):
    """Run with Rich live display."""
    try:
        from rich.console import Console
        from rich.layout import Layout
        from rich.live import Live
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        print("Visual mode requires 'rich': pip install rich", file=sys.stderr)
        sys.exit(1)

    console = Console()
    stats = WindowStats()
    recent_events: list[Text] = []
    max_recent = 15
    last_summary_time = time.time()

    def make_layout() -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
        )
        layout["body"].split_row(
            Layout(name="stats", ratio=1),
            Layout(name="events", ratio=2),
        )
        return layout

    def render_stats() -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(justify="right", style="dim")
        table.add_column(justify="left")

        elapsed = time.time() - last_summary_time
        rps = stats.requests / elapsed if elapsed > 0 else 0

        table.add_row("Requests:", f"{stats.requests}")
        table.add_row("Rate:", f"{rps:.1f}/s")
        table.add_row("Blocked:", f"[red]{stats.blocks}[/red]" if stats.blocks else "0")
        table.add_row("Warnings:", f"[yellow]{stats.warnings}[/yellow]" if stats.warnings else "0")
        table.add_row("", "")
        table.add_row("Avg latency:", f"{stats.avg_latency():.0f}ms" if stats.latencies else "-")
        table.add_row("P95 latency:", f"{stats.p95_latency():.0f}ms" if stats.latencies else "-")
        table.add_row("", "")

        # Status breakdown
        for bucket in ["2xx", "3xx", "4xx", "5xx"]:
            count = stats.by_status.get(bucket, 0)
            if count > 0:
                color = "green" if bucket == "2xx" else ("yellow" if bucket != "5xx" else "red")
                table.add_row(f"{bucket}:", f"[{color}]{count}[/{color}]")

        table.add_row("", "")

        # Top domains
        for domain, count in stats.top_domains(5):
            table.add_row(f"{domain[:20]}:", str(count))

        return Panel(table, title="[bold]Statistics[/bold]", border_style="blue")

    def render_events() -> Panel:
        text = Text()
        for event_text in recent_events[-max_recent:]:
            text.append_text(event_text)
            text.append("\n")
        return Panel(text, title="[bold]Recent Events[/bold]", border_style="cyan")

    def add_event(entry: dict, event_type: str):
        ts = format_ts(entry.get("ts", ""))
        host = entry.get("host", entry.get("domain", ""))
        decision = entry.get("decision", "")

        text = Text()
        text.append(f"{ts} ", style="dim")

        if decision == "block" or entry.get("blocked_by"):
            text.append("[BLOCK] ", style="bold red")
        elif event_type.startswith("security."):
            color = "yellow" if decision == "warn" else "cyan"
            label = event_type.replace("security.", "").upper()
            text.append(f"[{label}] ", style=color)
        elif event_type.startswith("admin."):
            text.append("[ADMIN] ", style="green")
        elif event_type.startswith("ops."):
            text.append("[OPS] ", style="cyan")
        else:
            text.append(f"[{event_type}] ", style="dim")

        text.append(host, style="cyan")

        if entry.get("reason"):
            text.append(f" - {entry['reason']}", style="dim")

        recent_events.append(text)
        if len(recent_events) > max_recent * 2:
            recent_events[:] = recent_events[-max_recent:]

    layout = make_layout()

    with Live(layout, console=console, refresh_per_second=4, screen=True) as live:
        layout["header"].update(
            Panel(
                Text("SafeYolo Log Monitor", justify="center", style="bold"),
                border_style="green",
            )
        )

        try:
            for line in source:
                entry = parse_line(line)
                if not entry:
                    continue

                event = entry.get("event", "")

                # Track stats
                if event in ("traffic.request", "traffic.response"):
                    host = entry.get("host", "")
                    status = entry.get("status", 0)
                    latency = entry.get("latency_ms")
                    if host:
                        stats.add_request(host, status, latency)

                # Notable events
                decision = entry.get("decision", "")
                if (
                    entry.get("blocked_by")
                    or decision == "block"
                    or event.startswith(("security.", "admin.", "ops."))
                ):
                    if decision == "block":
                        stats.blocks += 1
                    elif decision == "warn":
                        stats.warnings += 1
                    add_event(entry, event)

                # Update display
                layout["stats"].update(render_stats())
                layout["events"].update(render_events())

                # Reset stats periodically
                now = time.time()
                if now - last_summary_time >= interval:
                    stats = WindowStats()
                    last_summary_time = now

        except KeyboardInterrupt:
            pass


def run_text_mode(source: TextIO, interval: float, show_summary: bool):
    """Run in plain text mode."""
    stats = WindowStats()
    last_summary = time.time()

    print(f"{DIM}SafeYolo log tail - waiting for events...{RESET}", file=sys.stderr)
    if show_summary:
        print(f"{DIM}Blocks/warnings shown immediately, summaries every {interval:.0f}s{RESET}", file=sys.stderr)
    print(file=sys.stderr)

    try:
        for line in source:
            entry = parse_line(line)
            if not entry:
                continue

            process_entry(entry, stats)

            # Print summary periodically
            if show_summary:
                now = time.time()
                if now - last_summary >= interval:
                    print_summary(stats, now - last_summary)
                    stats = WindowStats()
                    last_summary = now

    except KeyboardInterrupt:
        # Final summary
        if show_summary:
            elapsed = time.time() - last_summary
            if stats.requests > 0:
                print(file=sys.stderr)
                print_summary(stats, elapsed)
        print(f"\n{DIM}Exiting.{RESET}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="Live tail of SafeYolo JSONL logs with summaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  docker logs -f safeyolo 2>&1 | python logtail.py
  tail -f logs/safeyolo.jsonl | python logtail.py
  python logtail.py --visual logs/safeyolo.jsonl
  python logtail.py --interval 10
        """,
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Log file to read (default: stdin)",
    )
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=5.0,
        help="Summary interval in seconds (default: 5)",
    )
    parser.add_argument(
        "--visual", "-v",
        action="store_true",
        help="Use Rich-based visual dashboard",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Disable periodic summaries (show events only)",
    )

    args = parser.parse_args()

    # Determine input source
    if args.file:
        try:
            source = open(args.file)
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        source = sys.stdin

    try:
        if args.visual:
            run_visual_mode(source, args.interval)
        else:
            run_text_mode(source, args.interval, not args.no_summary)
    finally:
        if args.file:
            source.close()


if __name__ == "__main__":
    main()
