#!/usr/bin/env python3
"""Render one supervised-agent Coord room as a live operator timeline."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import textwrap
from collections import deque
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from safeyolo.coord import api
from safeyolo.core.audit_schema import sanitize_for_log

SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"token|secret|password|cookie|private[_-]?key)\s*([:=])\s*([^\s,;]+)"
)
TOKEN_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[^\s,;]+"),
    re.compile(r"\b(?:sgw_|sk-|gh[pousr]_)[A-Za-z0-9._-]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}\b"),
)
URL_PATTERN = re.compile(r"https?://[^\s\]\[\"'<>]+")


def _time(message: dict[str, Any]) -> str:
    value = message.get("sent_at")
    if isinstance(value, int) and not isinstance(value, bool):
        return datetime.fromtimestamp(value / 1000, UTC).strftime("%H:%M:%SZ")
    return datetime.now(UTC).strftime("%H:%M:%SZ")


def _clean(value: Any, limit: int, *, redact: bool = False) -> str:
    text = sanitize_for_log(value, max_len=None)
    if redact:
        for pattern in TOKEN_PATTERNS:
            text = pattern.sub("<redacted>", text)
        text = SECRET_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}{match.group(2)}<redacted>",
            text,
        )

        def strip_query(match: re.Match[str]) -> str:
            raw = match.group(0)
            try:
                parts = urlsplit(raw)
            except ValueError:
                return "<invalid-url>"
            if not parts.query and not parts.fragment:
                return raw
            return urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")) + "?<omitted>"

        text = URL_PATTERN.sub(strip_query, text)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _event_line(
    event: dict[str, Any],
    limit: int,
    *,
    redact: bool = False,
    show_unknown: bool = False,
) -> tuple[str, str] | None:
    kind = event.get("type")
    if kind == "safeyolo.codex.stderr":
        return "STDERR", _clean(event.get("text", ""), limit, redact=redact)
    if kind == "safeyolo.supervisor":
        action = str(event.get("event", "event"))
        details = []
        for key in ("pid", "signal", "exit_code", "error_type", "message"):
            if key in event:
                details.append(f"{key}={event[key]}")
        label = "ERROR" if action in {"error", "crashed"} else "SUPERV"
        return label, _clean(" ".join((action, *details)), limit, redact=redact)
    if kind == "thread.started":
        return "SESSION", f"thread={event.get('thread_id', '?')}"
    if kind == "turn.started":
        return "TURN", "started"
    if kind == "turn.completed":
        return "DONE", "turn completed"
    if kind == "turn.failed":
        return "ERROR", _clean(event.get("error", "turn failed"), limit, redact=redact)
    if kind in {"item.started", "item.completed"}:
        item = event.get("item")
        if isinstance(item, dict):
            phase = str(kind).removeprefix("item.")
            item_type = item.get("type")
            if item.get("type") == "agent_message":
                return "AGENT", _clean(item.get("text", ""), limit, redact=redact)
            if item_type in {"reasoning", "agent_reasoning"}:
                return "THINK", _clean(item.get("text", ""), limit, redact=redact)
            if item.get("type") == "mcp_tool_call":
                arguments = item.get("arguments")
                detail = ""
                if isinstance(arguments, dict):
                    shown = []
                    for key in ("room_name", "since_sequence", "timeout_seconds"):
                        if key in arguments:
                            shown.append(f"{key}={arguments[key]}")
                    detail = " " + " ".join(shown) if shown else ""
                return (
                    "TOOL",
                    f"{phase} {item.get('server', 'mcp')}.{item.get('tool', 'tool')}"
                    f" status={item.get('status', '?')}{detail}",
                )
            if item_type in {"command_execution", "local_shell_call"}:
                command = item.get("command") or item.get("action") or item.get("arguments") or ""
                return "TOOL", f"{phase} command {_clean(command, limit, redact=redact)}"
            if item_type in {"function_call", "custom_tool_call"}:
                name = item.get("name") or item.get("tool") or "tool"
                return "TOOL", f"{phase} {name}"
            if item_type in {"function_call_output", "custom_tool_call_output"}:
                return "TOOL", f"{phase} result {item.get('call_id', '')}".strip()
            if item_type in {"web_search", "web_search_call"}:
                return "TOOL", f"{phase} web_search"
            if item_type in {"file_change", "file_write", "apply_patch"}:
                return "TOOL", f"{phase} {item_type}"
    if not show_unknown:
        return None
    return "EVENT", _clean(json.dumps(event, separators=(",", ":")), limit, redact=redact)


def _render(
    message: dict[str, Any],
    limit: int,
    mode: str = "rendered",
    colour: bool = False,
    redact: bool = False,
    show_unknown: bool = False,
) -> None:
    body = message.get("body")
    if not isinstance(body, str):
        return
    if mode == "json":
        print(json.dumps(message, sort_keys=True, separators=(",", ":")), flush=True)
        return
    if mode == "raw":
        sender = message.get("sender_agent_name") or message.get("sender_kind") or "unknown"
        print(f"[{_time(message)}] {sender}", flush=True)
        print(body, flush=True)
        return
    sender_kind = message.get("sender_kind")
    if sender_kind == "agent":
        try:
            event = json.loads(body)
        except json.JSONDecodeError:
            event = None
        if isinstance(event, dict):
            rendered = _event_line(
                event,
                limit,
                redact=redact,
                show_unknown=show_unknown,
            )
            if rendered is None:
                return
            label, text = rendered
        else:
            label, text = "CHAT", _clean(body, limit, redact=redact)
    else:
        label = "OP" if sender_kind == "operator" else "CHAT"
        text = _clean(body, limit, redact=redact)
    palette = {
        "SESSION": "36",
        "TURN": "34;1",
        "TOOL": "33",
        "AGENT": "32",
        "DONE": "32;1",
        "ERROR": "31;1",
        "STDERR": "31",
        "SUPERV": "36;1",
        "OP": "34;1",
        "CHAT": "32",
        "THINK": "35",
        "EVENT": "2",
    }
    shown_label = f"{label:7}"
    if colour:
        shown_label = f"\033[{palette.get(label, '0')}m{shown_label}\033[0m"
    print(f"[{_time(message)}] {shown_label} {text}", flush=True)


async def _watch(
    room: str,
    history_count: int,
    limit: int,
    mode: str,
    colour: bool,
    redact: bool,
    show_unknown: bool,
    once: bool,
) -> None:
    page = await api.read_room(
        room,
        "operator",
        "operator",
        since_sequence=0,
        limit=api.READ_PAGE_MAX,
    )
    history: deque[dict[str, Any]] = deque(page["messages"], maxlen=history_count)
    for message in history:
        _render(message, limit, mode, colour, redact, show_unknown)
    cursor = page["next_cursor"]
    if once:
        return
    if mode != "json":
        print(f"--- watching {room}; Ctrl-C stops ---", flush=True)

    while True:
        woke = await api.wait_for_message(
            room,
            "operator",
            "operator",
            since_sequence=cursor,
            timeout_seconds=300,
            limit=1,
            exclude_self=False,
        )
        if not woke["messages"]:
            continue
        while True:
            page = await api.read_room(
                room,
                "operator",
                "operator",
                since_sequence=cursor,
                limit=api.READ_PAGE_MAX,
            )
            for message in page["messages"]:
                _render(message, limit, mode, colour, redact, show_unknown)
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Example:
              uv run python contrib/watch-agent-room.py lens-agent
            """
        ),
    )
    parser.add_argument("room")
    parser.add_argument("--history", type=int, default=30)
    parser.add_argument("--max-text", type=int, default=240)
    parser.add_argument("--once", action="store_true", help="Print retained history and exit")
    parser.add_argument("--show-unknown", action="store_true", help="Show unknown Codex event types")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--raw", action="store_true", help="Show each message body unchanged")
    modes.add_argument("--json", action="store_true", help="Emit canonical Coord messages as JSONL")
    parser.add_argument(
        "--no-color",
        "--plain",
        action="store_true",
        help="Disable colour in the rendered view",
    )
    parser.add_argument("--redact", action="store_true", help="Redact common credential patterns")
    args = parser.parse_args()
    if args.history < 0 or args.max_text < 40:
        parser.error("invalid numeric option")
    mode = "json" if args.json else "raw" if args.raw else "rendered"
    colour = mode == "rendered" and sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
    try:
        asyncio.run(
            _watch(
                args.room,
                args.history,
                args.max_text,
                mode,
                colour,
                args.redact,
                args.show_unknown,
                args.once,
            )
        )
    except KeyboardInterrupt:
        print("\nwatch-agent-room: stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
