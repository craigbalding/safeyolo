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
    blocker = entry.get("blocked_by", entry.get("addon", "unknown"))
    host = entry.get("host", entry.get("domain", "?"))
    path = entry.get("path", "")
    reason = entry.get("reason", entry.get("rule", ""))
    fingerprint = entry.get("credential_fingerprint", "")

    print(f"{RED}{BOLD}[BLOCK]{RESET} {DIM}{ts}{RESET} {RED}{blocker}{RESET} blocked {CYAN}{host}{path}{RESET}", file=sys.stderr)
    if reason:
        print(f"        {DIM}reason:{RESET} {reason}", file=sys.stderr)
    if fingerprint:
        print(f"        {DIM}fingerprint:{RESET} {fingerprint[:20]}...", file=sys.stderr)


def print_warning(entry: dict, event_type: str):
    """Print a warning/info event."""
    ts = format_timestamp(entry.get("ts", ""))
    host = entry.get("host", entry.get("domain", "?"))
    decision = entry.get("decision", "warn")

    # New taxonomy: security.ratelimit
    if event_type == "security.ratelimit":
        wait_ms = entry.get("wait_ms", 0)
        color = RED if decision == "block" else YELLOW
        print(f"{color}[RATE]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} {decision} {DIM}(wait {wait_ms:.0f}ms){RESET}", file=sys.stderr)

    # New taxonomy: security.circuit
    elif event_type == "security.circuit":
        circuit_event = entry.get("circuit_event", "unknown")
        domain = entry.get("domain", host)
        if circuit_event == "block":
            print(f"{RED}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{domain}{RESET} blocked (circuit open)", file=sys.stderr)
        elif circuit_event == "open":
            print(f"{YELLOW}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{domain}{RESET} circuit opened", file=sys.stderr)
        elif circuit_event == "half_open":
            print(f"{GREEN}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{domain}{RESET} testing recovery", file=sys.stderr)
        elif circuit_event == "close":
            print(f"{GREEN}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{domain}{RESET} recovered", file=sys.stderr)
        else:
            print(f"{YELLOW}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{domain}{RESET} {circuit_event}", file=sys.stderr)

    # New taxonomy: security.credential
    elif event_type == "security.credential":
        rule = entry.get("rule", "")
        path = entry.get("path", "")
        fingerprint = entry.get("credential_fingerprint", "")[:16]
        reason = entry.get("reason", "")
        color = RED if decision == "block" else (YELLOW if decision == "warn" else GREEN)
        label = "CRED" if decision != "allow" else "CRED-OK"
        print(f"{color}[{label}]{RESET} {DIM}{ts}{RESET} {rule} -> {CYAN}{host}{path}{RESET} {DIM}[{decision}]{RESET}", file=sys.stderr)
        if reason:
            print(f"        {DIM}reason:{RESET} {reason} {DIM}fp:{fingerprint}{RESET}", file=sys.stderr)

    # New taxonomy: security.injection
    elif event_type == "security.injection":
        det_type = entry.get("detection_type", "sync")
        if det_type == "async":
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
            color = RED if decision == "block" else YELLOW
            print(f"{color}[INJECT]{RESET} {DIM}{ts}{RESET} {RED}{classification}{RESET} ({confidence:.0%}) -> {CYAN}{host}{RESET} {DIM}{model} {latency:.0f}ms [{decision}]{RESET}", file=sys.stderr)
        text_preview = entry.get("text_preview", "")
        if text_preview:
            preview = text_preview[:100].replace("\n", " ")
            if len(text_preview) > 100:
                preview += "..."
            print(f"        {DIM}text:{RESET} {preview}", file=sys.stderr)

    # New taxonomy: security.pattern
    elif event_type == "security.pattern":
        rule_id = entry.get("rule_id", "?")
        rule_name = entry.get("rule_name", "")
        color = RED if decision == "block" else (GREEN if decision == "redact" else YELLOW)
        print(f"{color}[PATTERN]{RESET} {DIM}{ts}{RESET} {rule_id} ({rule_name}) -> {CYAN}{host}{RESET} {DIM}[{decision}]{RESET}", file=sys.stderr)

    # New taxonomy: security.yara
    elif event_type == "security.yara":
        rules = entry.get("rules", [])
        rules_str = ", ".join(rules) if isinstance(rules, list) else str(rules)
        color = RED if decision == "block" else YELLOW
        print(f"{color}[YARA]{RESET} {DIM}{ts}{RESET} {rules_str} -> {CYAN}{host}{RESET} {DIM}[{decision}]{RESET}", file=sys.stderr)

    # Admin events
    elif event_type == "admin.approve":
        token = entry.get("token", "?")[:8]
        status = entry.get("status", "?")
        client_ip = entry.get("client_ip", "?")
        color = GREEN if status == "approved" else YELLOW
        print(f"{color}[ADMIN]{RESET} {DIM}{ts}{RESET} approve {token}... {DIM}status={status} from={client_ip}{RESET}", file=sys.stderr)

    elif event_type == "admin.deny":
        token = entry.get("token", "?")[:8]
        status = entry.get("status", "?")
        client_ip = entry.get("client_ip", "?")
        print(f"{RED}[ADMIN]{RESET} {DIM}{ts}{RESET} deny {token}... {DIM}status={status} from={client_ip}{RESET}", file=sys.stderr)

    elif event_type == "admin.mode_change":
        target = entry.get("target_addon", "?")
        new_mode = entry.get("new_mode", "?")
        client_ip = entry.get("client_ip", "?")
        color = RED if new_mode == "block" else GREEN
        print(f"{color}[ADMIN]{RESET} {DIM}{ts}{RESET} mode_change {target} -> {new_mode} {DIM}from={client_ip}{RESET}", file=sys.stderr)

    elif event_type == "admin.auth_failure":
        path = entry.get("path", "?")
        client_ip = entry.get("client_ip", "?")
        print(f"{RED}[ADMIN]{RESET} {DIM}{ts}{RESET} auth_failure {path} {DIM}from={client_ip}{RESET}", file=sys.stderr)

    # Legacy event names (backward compatibility)
    elif event_type == "rate_limited":
        wait_ms = entry.get("wait_ms", 0)
        print(f"{YELLOW}[RATE]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} throttled {DIM}(wait {wait_ms:.0f}ms){RESET}", file=sys.stderr)
    elif event_type in ("circuit_open", "circuit_half_open", "circuit_close"):
        state = event_type.replace("circuit_", "")
        color = GREEN if state in ("half_open", "close") else YELLOW
        print(f"{color}[CIRCUIT]{RESET} {DIM}{ts}{RESET} {CYAN}{host}{RESET} {state}", file=sys.stderr)
    elif event_type == "credential_violation":
        rule = entry.get("rule", "")
        path = entry.get("path", entry.get("request_path", ""))
        print(f"{YELLOW}[CRED]{RESET} {DIM}{ts}{RESET} {rule} -> {CYAN}{host}{path}{RESET}", file=sys.stderr)
    elif event_type == "injection_detection":
        classification = entry.get("classification", "?")
        confidence = entry.get("confidence", 0)
        print(f"{YELLOW}[INJECT]{RESET} {DIM}{ts}{RESET} {RED}{classification}{RESET} ({confidence:.0%}) -> {CYAN}{host}{RESET}", file=sys.stderr)
    elif event_type == "pattern_match":
        rule = entry.get("rule", "?")
        print(f"{YELLOW}[PATTERN]{RESET} {DIM}{ts}{RESET} {rule} -> {CYAN}{host}{RESET}", file=sys.stderr)
    elif event_type == "yara_match":
        rules = entry.get("rules", [])
        rules_str = ", ".join(rules) if isinstance(rules, list) else str(rules)
        print(f"{YELLOW}[YARA]{RESET} {DIM}{ts}{RESET} {rules_str} -> {CYAN}{host}{RESET}", file=sys.stderr)

    # Ops events
    elif event_type.startswith("ops."):
        addon = entry.get("addon", "?")
        print(f"{CYAN}[OPS]{RESET} {DIM}{ts}{RESET} {event_type} {DIM}addon={addon}{RESET}", file=sys.stderr)

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
    decision = entry.get("decision", "")

    # Blocked requests - either via blocked_by field or decision="block"
    if entry.get("blocked_by") or decision == "block":
        print_block(entry)
        stats.blocks += 1
        return True

    # Security events with warn decision
    security_events = {
        "security.credential", "security.injection", "security.pattern",
        "security.yara", "security.ratelimit", "security.circuit",
    }
    if event in security_events:
        print_warning(entry, event)
        if decision == "warn":
            stats.warnings += 1
        return True

    # Admin events (always show)
    admin_events = {
        "admin.approve", "admin.deny", "admin.mode_change", "admin.auth_failure",
    }
    if event in admin_events:
        print_warning(entry, event)
        return True

    # Ops events (show but don't count as warnings)
    if event.startswith("ops."):
        print_warning(entry, event)
        return True

    # Legacy warning events (backward compatibility)
    legacy_warning_events = {
        "rate_limited", "circuit_open", "circuit_half_open", "circuit_close",
        "credential_violation", "injection_detection", "pattern_match", "yara_match",
        "false_negative",
    }
    if event in legacy_warning_events:
        print_warning(entry, event)
        stats.warnings += 1
        return True

    # Normal request logging (new and legacy names)
    if event in ("traffic.request", "traffic.response", "request", "response", "request_complete"):
        host = entry.get("host", "")
        status = entry.get("status", entry.get("status_code", 0))
        latency = entry.get("ms", entry.get("latency_ms", entry.get("duration_ms")))
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
