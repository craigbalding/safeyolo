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
from safeyolo.coord.nats_client import NatsUnavailable
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


def _redact_text(text: str) -> str:
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

    return URL_PATTERN.sub(strip_query, text)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    return value


def _clean(value: Any, limit: int | None, *, redact: bool = False) -> str:
    text = sanitize_for_log(value, max_len=None)
    if redact:
        text = _redact_text(text)
    text = " ".join(text.split())
    if limit is None or len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _web_search_detail(
    item: dict[str, Any],
    phase: str,
    limit: int | None,
    *,
    redact: bool,
) -> str:
    """Render the useful destination or query from a Codex web event."""

    action = item.get("action")
    action = action if isinstance(action, dict) else {}
    action_queries = action.get("queries")
    if isinstance(action_queries, list):
        queries = [value for value in action_queries if isinstance(value, str) and value]
    else:
        queries = []
    query = action.get("query") or item.get("query")
    url = action.get("url") or item.get("url")
    if not isinstance(url, str) or not url:
        url = query if isinstance(query, str) and query.startswith(("http://", "https://")) else ""

    detail = f"{phase} web_search"
    if url:
        detail += f" url={url}"
    elif queries:
        detail += " queries=" + " | ".join(queries)
    elif isinstance(query, str) and query:
        detail += f" query={query}"
    return _clean(detail, limit, redact=redact)


def _mcp_detail(
    item: dict[str, Any],
    phase: str,
    limit: int | None,
    *,
    redact: bool,
) -> str:
    """Render bounded routing arguments without dumping request bodies."""

    arguments = item.get("arguments")
    arguments = arguments if isinstance(arguments, dict) else {}
    details = [
        f"{phase} {item.get('server', 'mcp')}.{item.get('tool', 'tool')}",
        f"status={item.get('status', '?')}",
    ]

    aliases = (
        (("room_name",), "room"),
        (("assignee",), "assignee"),
        (("target",), "target"),
        (("repository_full_name", "repo_full_name"), "repo"),
        (("issue_number",), "issue"),
        (("pr_number",), "pr"),
        (("path",), "path"),
        (("ref",), "ref"),
        (("commit_sha", "sha"), "sha"),
        (("head", "head_branch"), "head"),
        (("base", "base_branch"), "base"),
        (("branch", "branch_name"), "branch"),
        (("run_id",), "run"),
        (("job_id",), "job"),
        (("query",), "query"),
        (("url",), "url"),
        (("since_sequence",), "cursor"),
        (("timeout_seconds",), "timeout"),
        (("limit",), "limit"),
    )
    for source_keys, shown_key in aliases:
        value = next((arguments[key] for key in source_keys if key in arguments), None)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and value != "":
            details.append(f"{shown_key}={value}")

    start = arguments.get("start_line")
    end = arguments.get("end_line")
    if isinstance(start, int) and not isinstance(start, bool):
        lines = str(start)
        if isinstance(end, int) and not isinstance(end, bool):
            lines += f"-{end}"
        details.append(f"lines={lines}")

    error = item.get("error")
    if error:
        details.append(f"error={error}")
    return _clean(" ".join(details), limit, redact=redact)


def _file_change_detail(
    item: dict[str, Any],
    phase: str,
    limit: int | None,
    *,
    redact: bool,
) -> str:
    changes = item.get("changes")
    shown = []
    if isinstance(changes, list):
        for change in changes:
            if not isinstance(change, dict):
                continue
            path = change.get("path")
            if not isinstance(path, str) or not path:
                continue
            kind = change.get("kind")
            shown.append(f"{kind}:{path}" if isinstance(kind, str) and kind else path)
    detail = f"{phase} file_change"
    if shown:
        detail += " " + " ".join(shown)
    return _clean(detail, limit, redact=redact)


def _turn_completed_detail(event: dict[str, Any]) -> str:
    usage = event.get("usage")
    if not isinstance(usage, dict):
        return "turn completed"
    labels = (
        ("input_tokens", "input"),
        ("cached_input_tokens", "cached"),
        ("output_tokens", "output"),
        ("reasoning_output_tokens", "reasoning"),
    )
    shown = []
    for key, label in labels:
        value = usage.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            shown.append(f"{label}={value:,}")
    if not shown:
        return "turn completed"
    return "turn completed tokens " + " ".join(shown)


def _pi_tool_detail(
    event: dict[str, Any],
    phase: str,
    limit: int | None,
    *,
    redact: bool,
) -> str:
    name = event.get("toolName")
    name = name if isinstance(name, str) and name else "tool"
    arguments = event.get("args")
    arguments = arguments if isinstance(arguments, dict) else {}
    details = [phase, name]
    for key in (
        "command",
        "path",
        "offset",
        "limit",
        "room_name",
        "target",
        "query",
        "url",
    ):
        value = arguments.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool) and value != "":
            details.append(f"{key}={value}")
    if phase == "completed":
        details.append("status=error" if event.get("isError") is True else "status=ok")
    return _clean(" ".join(details), limit, redact=redact)


def _pi_message_detail(message: dict[str, Any], limit: int | None, *, redact: bool) -> str:
    content = message.get("content")
    text = ""
    if isinstance(content, list):
        fragments = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict)
            and block.get("type") == "text"
            and isinstance(block.get("text"), str)
        ]
        text = " ".join(fragment for fragment in fragments if fragment)
    if text:
        return _clean(text, limit, redact=redact)
    usage = message.get("usage")
    if not isinstance(usage, dict):
        return "assistant message"
    labels = (
        ("input", "input"),
        ("cacheRead", "cached"),
        ("output", "output"),
        ("reasoning", "reasoning"),
    )
    shown = [
        f"{label}={usage[key]:,}"
        for key, label in labels
        if isinstance(usage.get(key), int) and not isinstance(usage[key], bool)
    ]
    return "assistant message" + (" tokens " + " ".join(shown) if shown else "")


def _event_line(
    event: dict[str, Any],
    limit: int | None,
    *,
    redact: bool = False,
    show_unknown: bool = False,
) -> tuple[str, str] | None:
    kind = event.get("type")
    if kind in {"safeyolo.codex.oversize", "safeyolo.pi.oversize"}:
        original_type = str(event.get("original_type", "unknown"))
        summary = event.get("summary")
        detail = original_type
        label = "EVENT"
        if isinstance(summary, dict):
            item_type = summary.get("type")
            if item_type in {"command_execution", "local_shell_call"}:
                phase = original_type.removeprefix("item.")
                detail = f"{phase} command {summary.get('command', '')}".rstrip()
                label = "TOOL"
            elif item_type == "mcp_tool_call":
                phase = original_type.removeprefix("item.")
                detail = _mcp_detail(summary, phase, limit, redact=redact)
                label = "TOOL"
            elif item_type == "agent_message":
                detail = str(summary.get("text", ""))
                label = "AGENT"
            elif item_type in {"reasoning", "agent_reasoning"}:
                detail = str(summary.get("text", ""))
                label = "THINK"
            elif item_type in {"function_call", "custom_tool_call"}:
                detail = (
                    f"{original_type.removeprefix('item.')} "
                    f"{summary.get('name') or summary.get('tool') or 'tool'}"
                )
                label = "TOOL"
            elif item_type in {"web_search", "web_search_call"}:
                detail = _web_search_detail(
                    summary,
                    original_type.removeprefix("item."),
                    limit,
                    redact=redact,
                )
                label = "TOOL"
            elif item_type in {"file_change", "file_write", "apply_patch"}:
                detail = _file_change_detail(
                    summary,
                    original_type.removeprefix("item."),
                    limit,
                    redact=redact,
                )
                label = "TOOL"
            elif original_type in {"safeyolo.codex.stderr", "safeyolo.pi.stderr"}:
                detail = str(summary.get("text", ""))
                label = "STDERR"
            elif isinstance(summary.get("toolName"), str):
                detail = _pi_tool_detail(
                    summary,
                    "completed" if original_type == "tool_execution_end" else "started",
                    limit,
                    redact=redact,
                )
                label = "ERROR" if summary.get("isError") == "true" else "TOOL"
            elif original_type == "safeyolo.supervisor":
                action = str(summary.get("event", "event"))
                detail = f"{action} {summary.get('message', '')}".rstrip()
                label = "ERROR" if action in {"error", "crashed"} else "SUPERV"
        marker = (
            "[middle snipped; "
            f"original_bytes={event.get('original_bytes', '?')} "
            f"omitted_bytes={event.get('omitted_middle_bytes', '?')} "
            f"sha256={event.get('sha256', '?')}]"
        )
        detail_limit = max(1, limit - len(marker) - 1)
        return label, f"{_clean(detail, detail_limit, redact=redact)} {marker}"
    if kind in {"safeyolo.codex.stderr", "safeyolo.pi.stderr"}:
        return "STDERR", _clean(event.get("text", ""), limit, redact=redact)
    if kind == "safeyolo.supervisor":
        action = str(event.get("event", "event"))
        details = []
        for key in (
            "pid",
            "signal",
            "exit_code",
            "status",
            "path",
            "retry_after",
            "error_type",
            "message",
        ):
            if key in event:
                details.append(f"{key}={event[key]}")
        label = "ERROR" if action in {"error", "crashed"} else "SUPERV"
        return label, _clean(" ".join((action, *details)), limit, redact=redact)
    if kind == "error":
        return "ERROR", _clean(event.get("message", "error"), limit, redact=redact)
    if kind == "thread.started":
        return "SESSION", f"thread={event.get('thread_id', '?')}"
    if kind == "turn.started":
        return "TURN", "started"
    if kind == "turn.completed":
        return "DONE", _turn_completed_detail(event)
    if kind == "turn.failed":
        return "ERROR", _clean(event.get("error", "turn failed"), limit, redact=redact)
    if kind == "session":
        return "SESSION", f"session={event.get('id', '?')}"
    if kind == "agent_start":
        return "TURN", "started"
    if kind == "agent_end":
        return "DONE", "turn completed"
    if kind in {"tool_execution_start", "tool_execution_end"}:
        phase = "started" if kind.endswith("start") else "completed"
        label = "ERROR" if event.get("isError") is True else "TOOL"
        return label, _pi_tool_detail(event, phase, limit, redact=redact)
    if kind == "message_end":
        message = event.get("message")
        if isinstance(message, dict) and message.get("role") == "assistant":
            label = "ERROR" if message.get("stopReason") in {"error", "aborted"} else "AGENT"
            return label, _pi_message_detail(message, limit, redact=redact)
    if kind == "extension_error":
        return "ERROR", _clean(event.get("error", "extension failed"), limit, redact=redact)
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
                detail = _mcp_detail(item, phase, limit, redact=redact)
                label = "ERROR" if item.get("error") or item.get("status") == "failed" else "TOOL"
                return label, detail
            if item_type in {"command_execution", "local_shell_call"}:
                command = item.get("command") or item.get("action") or item.get("arguments") or ""
                prefix = f"{phase} command"
                exit_code = item.get("exit_code")
                if isinstance(exit_code, int) and not isinstance(exit_code, bool):
                    prefix += f" rc={exit_code}"
                label = "ERROR" if isinstance(exit_code, int) and exit_code != 0 else "TOOL"
                return label, _clean(f"{prefix} {command}", limit, redact=redact)
            if item_type in {"function_call", "custom_tool_call"}:
                name = item.get("name") or item.get("tool") or "tool"
                return "TOOL", f"{phase} {name}"
            if item_type in {"function_call_output", "custom_tool_call_output"}:
                return "TOOL", f"{phase} result {item.get('call_id', '')}".strip()
            if item_type in {"web_search", "web_search_call"}:
                return "TOOL", _web_search_detail(item, phase, limit, redact=redact)
            if item_type in {"file_change", "file_write", "apply_patch"}:
                return "TOOL", _file_change_detail(
                    item,
                    phase,
                    limit,
                    redact=redact,
                )
            if item_type == "error":
                return "ERROR", _clean(item.get("message", "error"), limit, redact=redact)
    if not show_unknown:
        return None
    return "EVENT", _clean(json.dumps(event, separators=(",", ":")), limit, redact=redact)


def _render(
    message: dict[str, Any],
    limit: int | None,
    mode: str = "rendered",
    colour: bool = False,
    redact: bool = False,
    show_unknown: bool = False,
) -> None:
    body = message.get("body")
    if not isinstance(body, str):
        return
    if mode == "json":
        shown = _redact_value(message) if redact else message
        print(json.dumps(shown, sort_keys=True, separators=(",", ":")), flush=True)
        return
    if mode == "raw":
        sender = message.get("sender_agent_name") or message.get("sender_kind") or "unknown"
        print(f"[{_time(message)}] {sender}", flush=True)
        print(_redact_text(body) if redact else body, flush=True)
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


def _connection_line(state: str, detail: str, *, colour: bool) -> None:
    label = f"{'CONN':7}"
    if colour:
        code = "31;1" if state == "lost" else "32;1"
        label = f"\033[{code}m{label}\033[0m"
    now = datetime.now(UTC).strftime("%H:%M:%SZ")
    print(f"[{now}] {label} {state} {detail}".rstrip(), flush=True)


async def _watch(
    room: str,
    history_count: int,
    limit: int | None,
    mode: str,
    colour: bool,
    redact: bool,
    show_unknown: bool,
    once: bool,
) -> None:
    failures = 0
    while True:
        try:
            history: deque[dict[str, Any]] = deque(maxlen=history_count)
            cursor = 0
            while True:
                page = await api.read_room(
                    room,
                    "operator",
                    "operator",
                    since_sequence=cursor,
                    limit=api.READ_PAGE_MAX,
                )
                history.extend(page["messages"])
                cursor = page["next_cursor"]
                if not page["has_more"]:
                    break
            break
        except NatsUnavailable as exc:
            if once:
                raise
            failures += 1
            delay = min(2 ** (failures - 1), 30)
            _connection_line(
                "lost",
                f"NATS unavailable; retrying in {delay}s: {_clean(exc, limit)}",
                colour=colour,
            )
            await asyncio.sleep(delay)
    if failures:
        _connection_line("recovered", "retained history is readable", colour=colour)
    for message in history:
        _render(message, limit, mode, colour, redact, show_unknown)
    if once:
        return
    if mode != "json":
        print(f"--- watching {room}; Ctrl-C stops ---", flush=True)

    while True:
        try:
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
                if failures:
                    _connection_line("recovered", "room wait is healthy", colour=colour)
                    failures = 0
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
            if failures:
                _connection_line("recovered", f"cursor={cursor}", colour=colour)
                failures = 0
        except NatsUnavailable as exc:
            failures += 1
            delay = min(2 ** (failures - 1), 30)
            _connection_line(
                "lost",
                f"NATS unavailable; cursor={cursor} retrying in {delay}s: {_clean(exc, limit)}",
                colour=colour,
            )
            await asyncio.sleep(delay)


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
    parser.add_argument(
        "--max-text",
        type=int,
        default=None,
        help="Limit rendered event text (default: show complete content)",
    )
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
    if args.history < 0 or (args.max_text is not None and args.max_text < 40):
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
