"""Reusable readers for SafeYolo's durable audit-event stream.

The JSONL file remains the source of truth.  Consumers may use these helpers
to reconstruct current state and then follow new events without importing a
terminal UI.
"""

from __future__ import annotations

import json
import os
import time
from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path

from .audit_schema import InvalidAuditEvent, parse_audit_event

AuditEvent = dict
EventParser = Callable[[str], AuditEvent | None]
StatusHandler = Callable[[str], None]
ErrorHandler = Callable[[Exception], None]
StopPredicate = Callable[[], bool]


class AuditLineParser:
    """Parse and validate audit lines, with optional event-id deduplication."""

    def __init__(
        self,
        *,
        on_schema_drift: Callable[[InvalidAuditEvent], None] | None = None,
        seen_event_ids: int | None = 2048,
    ) -> None:
        self._on_schema_drift = on_schema_drift
        self._seen_limit = seen_event_ids
        self._seen_ids: deque[str] = deque()
        self._seen_set: set[str] = set()

    def parse(self, line: str) -> AuditEvent | None:
        """Return one event, or ``None`` for invalid JSON or a duplicate ID."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return None

        try:
            parse_audit_event(event)
        except InvalidAuditEvent as exc:
            if self._on_schema_drift is not None:
                self._on_schema_drift(exc)
            if not isinstance(event, dict):
                return None

        event_id = event.get("event_id")
        if self._seen_limit is not None and isinstance(event_id, str) and event_id:
            if event_id in self._seen_set:
                return None
            self._seen_ids.append(event_id)
            self._seen_set.add(event_id)
            if len(self._seen_ids) > self._seen_limit:
                self._seen_set.discard(self._seen_ids.popleft())

        return event


def follow_jsonl(
    path: Path,
    *,
    parse_line: EventParser,
    follow: bool = True,
    tick_interval: float = 0,
    on_status: StatusHandler | None = None,
    should_stop: StopPredicate | None = None,
    initial_position: int | None = None,
    reopen_check_interval: float = 2.0,
) -> Iterator[AuditEvent | None]:
    """Read a JSONL file and optionally follow replacements and truncations.

    In follow mode the first open starts at EOF.  A replacement, recreation,
    or truncation starts at byte zero so events written during a proxy restart
    are not missed.  ``None`` is yielded at ``tick_interval`` while idle.
    """
    first_open = True
    last_tick = time.monotonic()
    last_reopen_check = last_tick

    while True:
        if should_stop is not None and should_stop():
            return
        while not path.exists():
            if not follow:
                return
            if should_stop is not None and should_stop():
                return
            if first_open and on_status is not None:
                on_status(f"waiting:{path}")
            time.sleep(0.5)

        try:
            with path.open() as stream:
                inode = os.fstat(stream.fileno()).st_ino
                if follow and first_open:
                    if initial_position is None:
                        stream.seek(0, os.SEEK_END)
                    else:
                        stream.seek(initial_position)
                first_open = False

                while True:
                    if should_stop is not None and should_stop():
                        return
                    line = stream.readline()
                    if line:
                        stripped = line.strip()
                        if stripped:
                            event = parse_line(stripped)
                            if event is not None:
                                yield event
                        continue

                    if not follow:
                        return

                    time.sleep(0.1)
                    now = time.monotonic()
                    if tick_interval > 0 and now - last_tick >= tick_interval:
                        last_tick = now
                        yield None

                    if now - last_reopen_check < reopen_check_interval:
                        continue
                    last_reopen_check = now

                    try:
                        stat = path.stat()
                    except FileNotFoundError:
                        if on_status is not None:
                            on_status("removed")
                        break
                    except OSError:
                        continue

                    if stat.st_ino != inode:
                        if on_status is not None:
                            on_status("rotated")
                        break
                    if stat.st_size < stream.tell():
                        if on_status is not None:
                            on_status("truncated")
                        break
        except FileNotFoundError:
            continue


def approval_dedup_key(event: AuditEvent) -> str:
    """Return the canonical approval key used by current operator clients."""
    approval = event.get("approval", {})
    return f"{approval.get('key', '')}:{approval.get('target', '')}"


def resolved_approval_key(event: AuditEvent) -> str | None:
    """Return the approval key resolved by an operator audit event."""
    event_type = event.get("event", "")
    details = event.get("details", {})

    if event_type in ("admin.approval_added", "admin.denial"):
        cred_id = details.get("cred_id", "")
        destination = details.get("destination", "")
        if cred_id and destination:
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

    if event_type in ("admin.host_allowed", "admin.host_denied"):
        host = details.get("host", "")
        return f"{host}:{host}" if host else None

    if event_type in ("plumb.approved", "plumb.denied"):
        request_id = details.get("request_id", "")
        participants = details.get("participants", [])
        if request_id and participants:
            return f"{request_id}:{','.join(participants)}"

    if event_type == "admin.desktop_presented":
        agent_id = details.get("agent_id", "")
        if agent_id:
            return f"desktop.present:desktop:{agent_id}"

    return None


def scan_pending_approvals(
    log_path: Path,
    *,
    max_lines: int | None = 50_000,
    on_error: ErrorHandler | None = None,
) -> tuple[list[AuditEvent], set[str]]:
    """Reconstruct unresolved approval requests from the durable audit log."""
    if not log_path.exists():
        return [], set()

    recent_lines: deque[str] = deque(maxlen=max_lines)
    try:
        with log_path.open() as stream:
            recent_lines.extend(stream)
    except OSError as exc:
        if on_error is not None:
            on_error(exc)
        return [], set()

    parsed_events: list[AuditEvent] = []
    resolved_keys: set[str] = set()
    for line in reversed(recent_lines):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        parsed_events.append(event)
        if resolved_key := resolved_approval_key(event):
            resolved_keys.add(resolved_key)

    pending_by_key: dict[str, AuditEvent] = {}
    for event in parsed_events:
        approval = event.get("approval", {})
        if approval and approval.get("required"):
            key = approval_dedup_key(event)
            if key not in pending_by_key and key not in resolved_keys:
                pending_by_key[key] = event

    pending = list(pending_by_key.values())
    pending.sort(key=lambda event: event.get("ts", ""))
    return pending, resolved_keys
