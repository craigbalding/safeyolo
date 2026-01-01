#!/usr/bin/env python3
"""
logtail.py - Live tail of SafeYolo JSONL logs with summaries

Shows warnings/blocks immediately, prints 5-second traffic summaries.

Usage:
    # Tail docker logs
    docker logs -f safeyolo 2>&1 | python scripts/logtail.py

    # Tail a log file
    tail -f logs/safeyolo.jsonl | python scripts/logtail.py

    # From stored logs
    cat logs/safeyolo.jsonl | python scripts/logtail.py
"""

import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

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

    def top_domains(self, n: int = 3) -> list:
        return sorted(self.by_domain.items(), key=lambda x: -x[1])[:n]


def format_timestamp(ts_str: str) -> str:
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
    ts = format_timestamp(entry.get("ts", ""))
    blocker = entry.get("blocked_by", "unknown")
    host = entry.get("host", entry.get("domain", "?"))
    path = entry.get("path", "")
    reason = entry.get("block_reason", entry.get("rule", ""))

    print(f"{RED}{BOLD}[BLOCK]{RESET} {DIM}{ts}{RESET} {RED}{blocker}{RESET} blocked {CYAN}{host}{path}{RESET}", file=sys.stderr)
    if reason:
        print(f"        {DIM}reason:{RESET} {reason}", file=sys.stderr)


def print_warning(entry: dict, event_type: str):
    """Print a warning event."""
    ts = format_timestamp(entry.get("ts", ""))
    host = entry.get("host", entry.get("domain", "?"))

    if event_type == "rate_limited":
        wait_ms = entry.get("wait_ms", 0)
        print(f"{YELLOW}[RATE]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} throttled {DIM}(wait {wait_ms:.0f}ms){RESET}", file=sys.stderr)
    elif event_type == "circuit_open":
        print(f"{YELLOW}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} circuit opened", file=sys.stderr)
    elif event_type == "circuit_half_open":
        print(f"{GREEN}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} testing recovery", file=sys.stderr)
    elif event_type == "circuit_close":
        print(f"{GREEN}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} recovered", file=sys.stderr)
    elif event_type == "credential_violation":
        cred_type = entry.get("credential_type", "credential")
        rule = entry.get("rule", "")
        header = entry.get("header", "")
        path = entry.get("request_path", entry.get("path", ""))
        print(f"{YELLOW}[CRED]{RESET} {DIM}{ts}{RESET} {cred_type} -> {CYAN}{host}{path}{RESET}", file=sys.stderr)
        if rule or header:
            detail = f"rule={rule}" if rule else ""
            if header:
                detail += f" header={header}" if detail else f"header={header}"
            print(f"        {DIM}{detail}{RESET}", file=sys.stderr)
    elif event_type == "injection_detection":
        det_type = entry.get("type", "detection")
        # Handle both sync (detection) and async (async_detection) formats
        if det_type == "async_detection":
            primary_class = entry.get("primary_classification", "safe")
            secondary_class = entry.get("secondary_classification", "?")
            confidence = entry.get("secondary_confidence", 0)
            model = entry.get("secondary_model", "?")
            latency = entry.get("secondary_latency_ms", 0)
            print(f"{YELLOW}[INJECT]{RESET} {DIM}{ts}{RESET} async: {primary_class}->{RED}{secondary_class}{RESET} ({confidence:.0%}) {DIM}{model} {latency:.0f}ms{RESET}", file=sys.stderr)
        else:
            classification = entry.get("classification", "?")
            confidence = entry.get("confidence", 0)
            model = entry.get("model", "?")
            latency = entry.get("latency_ms", 0)
            print(f"{YELLOW}[INJECT]{RESET} {DIM}{ts}{RESET} {RED}{classification}{RESET} ({confidence:.0%}) -> {CYAN}{host}{RESET} {DIM}{model} {latency:.0f}ms{RESET}", file=sys.stderr)
        # Show text preview on next line
        text_preview = entry.get("text_preview", "")
        if text_preview:
            # Truncate and clean up for display
            preview = text_preview[:100].replace("\n", " ")
            if len(text_preview) > 100:
                preview += "..."
            print(f"        {DIM}text:{RESET} {preview}", file=sys.stderr)
    elif event_type == "pattern_match":
        rule = entry.get("rule", "?")
        print(f"{YELLOW}[PATTERN]{RESET} {DIM}{ts}{RESET} {rule} -> {CYAN}{host}{RESET}", file=sys.stderr)
    elif event_type == "yara_match":
        rules = entry.get("rules", [])
        rules_str = ", ".join(rules) if isinstance(rules, list) else str(rules)
        print(f"{YELLOW}[YARA]{RESET} {DIM}{ts}{RESET} {rules_str} -> {CYAN}{host}{RESET}", file=sys.stderr)
    else:
        print(f"{YELLOW}[WARN]{RESET} {DIM}{ts}{RESET} {event_type} {CYAN}{host}{RESET}", file=sys.stderr)


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
    max_lat = stats.max_latency()
    lat_str = f"{avg_lat:.0f}ms" if avg_lat else "-"
    if max_lat > avg_lat * 2 and max_lat > 100:
        lat_str += f" {DIM}(max {max_lat:.0f}){RESET}"

    # Blocks/warnings indicator
    alert_str = ""
    if stats.blocks > 0:
        alert_str += f" {RED}{stats.blocks} blocked{RESET}"
    if stats.warnings > 0:
        alert_str += f" {YELLOW}{stats.warnings} warn{RESET}"

    now = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{now}]{RESET} {stats.requests} req ({rps:.1f}/s) {status_str} lat={lat_str} {DIM}{domains_str}{RESET}{alert_str}", file=sys.stderr)


def process_entry(entry: dict, stats: WindowStats) -> bool:
    """Process a log entry. Returns True if it was a notable event."""
    event = entry.get("event", "")

    # Blocked requests
    if entry.get("blocked_by") or event.endswith("_blocked"):
        print_block(entry)
        stats.blocks += 1
        return True

    # Warning events
    warning_events = {
        "rate_limited", "circuit_open", "circuit_half_open", "circuit_close",
        "credential_violation", "injection_detection", "pattern_match", "yara_match",
        "false_negative",
    }
    if event in warning_events:
        print_warning(entry, event)
        stats.warnings += 1
        return True

    # Normal request logging
    if event in ("request", "response", "request_complete"):
        host = entry.get("host", "")
        status = entry.get("status", entry.get("status_code", 0))
        latency = entry.get("latency_ms", entry.get("duration_ms"))
        if host:
            stats.add_request(host, status, latency)

    return False


def main():
    stats = WindowStats()
    last_summary = time.time()
    summary_interval = 5.0

    print(f"{DIM}SafeYolo log tail - waiting for events...{RESET}", file=sys.stderr)
    print(f"{DIM}Blocks/warnings shown immediately, summaries every {summary_interval:.0f}s{RESET}", file=sys.stderr)
    print(file=sys.stderr)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue

            # Try to parse as JSON
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                # Not JSON - might be docker log prefix or other output
                # Check if it contains JSON after a prefix
                if "{" in line:
                    json_start = line.index("{")
                    try:
                        entry = json.loads(line[json_start:])
                    except json.JSONDecodeError:
                        continue
                else:
                    continue

            process_entry(entry, stats)

            # Print summary periodically
            now = time.time()
            if now - last_summary >= summary_interval:
                print_summary(stats, now - last_summary)
                stats = WindowStats()
                last_summary = now

    except KeyboardInterrupt:
        # Final summary
        elapsed = time.time() - last_summary
        if stats.requests > 0:
            print(file=sys.stderr)
            print_summary(stats, elapsed)
        print(f"\n{DIM}Exiting.{RESET}", file=sys.stderr)


if __name__ == "__main__":
    main()
