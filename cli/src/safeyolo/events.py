"""Event logging for SafeYolo CLI.

Writes agent lifecycle events to the shared JSONL audit log,
matching the format used by the proxy addons.
"""

import json
import logging
import sys
from datetime import UTC, datetime

from .config import get_logs_dir

log = logging.getLogger("safeyolo.events")


def write_event(event: str, **data) -> None:
    """Write an event to the JSONL audit log.

    Args:
        event: Event type using taxonomy (e.g., "agent.started")
        **data: Event-specific fields
    """
    log_path = get_logs_dir(create=True) / "safeyolo.jsonl"
    entry = {
        "ts": datetime.now(UTC).isoformat(),
        "event": event,
        **data,
    }
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[safeyolo] Event log write failed: {type(e).__name__}: {e}", file=sys.stderr)
