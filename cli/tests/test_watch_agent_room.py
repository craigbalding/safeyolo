"""Tests for the supervised-agent Coord room renderer."""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WATCHER_PATH = REPO_ROOT / "contrib/watch-agent-room.py"


@pytest.fixture(scope="module")
def watcher_module():
    spec = importlib.util.spec_from_file_location("watch_agent_room", WATCHER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_renders_operator_and_agent_events_in_one_timeline(watcher_module, capsys):
    watcher_module._render(
        {
            "sent_at": 1_788_342_431_000,
            "sender_kind": "operator",
            "sender_agent_name": None,
            "body": "Report the current cursor.",
        },
        240,
    )
    watcher_module._render(
        {
            "sent_at": 1_788_342_432_000,
            "sender_kind": "agent",
            "sender_agent_name": "lens",
            "body": json.dumps(
                {
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": "This cycle received cursor 4.",
                    },
                }
            ),
        },
        240,
    )

    output = capsys.readouterr().out
    assert "OP      Report the current cursor." in output
    assert "AGENT   This cycle received cursor 4." in output


def test_renders_wait_event_without_full_tool_result(watcher_module):
    label, detail = watcher_module._event_line(
        {
            "type": "item.completed",
            "item": {
                "type": "mcp_tool_call",
                "server": "safeyolo-coord",
                "tool": "wait_for_coord",
                "status": "completed",
                "arguments": {
                    "since_sequence": 8,
                    "timeout_seconds": 300,
                },
                "result": {"large": "payload"},
            },
        },
        240,
    )

    assert label == "TOOL"
    assert "cursor=8" in detail
    assert "payload" not in detail


def test_renders_mcp_locator_arguments_without_request_body(watcher_module):
    label, detail = watcher_module._event_line(
        {
            "type": "item.started",
            "item": {
                "type": "mcp_tool_call",
                "server": "github",
                "tool": "fetch_file",
                "status": "in_progress",
                "arguments": {
                    "repository_full_name": "craigbalding/safeyolo",
                    "path": "cli/src/safeyolo/coord/api.py",
                    "ref": "abc123",
                    "start_line": 100,
                    "end_line": 140,
                    "content": "do not render this",
                },
            },
        },
        None,
    )

    assert label == "TOOL"
    assert "repo=craigbalding/safeyolo" in detail
    assert "path=cli/src/safeyolo/coord/api.py" in detail
    assert "ref=abc123" in detail
    assert "lines=100-140" in detail
    assert "do not render this" not in detail


def test_renders_file_change_paths_and_kinds(watcher_module):
    assert watcher_module._event_line(
        {
            "type": "item.completed",
            "item": {
                "type": "file_change",
                "changes": [
                    {"kind": "update", "path": "/workspace/one.py"},
                    {"kind": "add", "path": "/workspace/two.py"},
                ],
            },
        },
        None,
    ) == (
        "TOOL",
        "completed file_change update:/workspace/one.py add:/workspace/two.py",
    )


@pytest.mark.parametrize(
    ("exit_code", "label"),
    [(0, "TOOL"), (2, "ERROR")],
)
def test_renders_command_exit_code(watcher_module, exit_code, label):
    assert watcher_module._event_line(
        {
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "pytest -q",
                "exit_code": exit_code,
            },
        },
        None,
    ) == (label, f"completed command rc={exit_code} pytest -q")


def test_renders_turn_token_usage(watcher_module):
    assert watcher_module._event_line(
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 48210,
                "cached_input_tokens": 45312,
                "output_tokens": 1106,
                "reasoning_output_tokens": 384,
            },
        },
        None,
    ) == (
        "DONE",
        "turn completed tokens input=48,210 cached=45,312 output=1,106 reasoning=384",
    )


def test_renders_top_level_and_item_errors(watcher_module):
    assert watcher_module._event_line(
        {"type": "error", "message": "provider failed"}, None
    ) == ("ERROR", "provider failed")
    assert watcher_module._event_line(
        {
            "type": "item.completed",
            "item": {"type": "error", "message": "tool failed"},
        },
        None,
    ) == ("ERROR", "tool failed")


@pytest.mark.parametrize(
    ("item", "shown"),
    [
        (
            {
                "type": "web_search",
                "query": "site:developers.openai.com/codex rules",
                "action": {
                    "type": "search",
                    "query": "site:developers.openai.com/codex rules",
                },
            },
            "query=site:developers.openai.com/codex rules",
        ),
        (
            {
                "type": "web_search",
                "query": "summarized",
                "action": {
                    "type": "search",
                    "queries": ["first query", "second query"],
                },
            },
            "queries=first query | second query",
        ),
        (
            {
                "type": "web_search",
                "query": "https://developers.openai.com/codex/rules",
                "action": {"type": "other"},
            },
            "url=https://developers.openai.com/codex/rules",
        ),
    ],
)
def test_renders_web_search_destination_or_query(watcher_module, item, shown):
    assert watcher_module._event_line(
        {"type": "item.completed", "item": item},
        None,
    ) == ("TOOL", f"completed web_search {shown}")


def test_web_search_url_uses_optional_redaction(watcher_module):
    event = {
        "type": "item.completed",
        "item": {
            "type": "web_search",
            "action": {
                "type": "open",
                "url": "https://example.test/page?token=secret-value",
            },
        },
    }

    assert "?token=secret-value" in watcher_module._event_line(event, None)[1]
    assert "?\u003comitted\u003e" in watcher_module._event_line(
        event,
        None,
        redact=True,
    )[1]


def test_raw_mode_preserves_message_body(watcher_module, capsys):
    body = '{"type":"turn.started","extra":"preserve spacing"}'

    watcher_module._render(
        {
            "sent_at": 1_788_342_432_000,
            "sender_kind": "agent",
            "sender_agent_name": "lens",
            "body": body,
        },
        40,
        "raw",
    )

    assert capsys.readouterr().out.splitlines()[-1] == body


def test_json_mode_emits_canonical_message_as_jsonl(watcher_module, capsys):
    message = {
        "msg_id": "msg-one",
        "sent_at": 1_788_342_432_000,
        "sender_kind": "operator",
        "sender_agent_id": None,
        "sender_agent_name": None,
        "body": "Continue.",
        "sequence": 4,
    }

    watcher_module._render(message, 40, "json")

    assert json.loads(capsys.readouterr().out) == message


def test_rendered_mode_shows_content_by_default_and_redacts_only_on_request(
    watcher_module,
):
    value = "token=visible-value"

    assert watcher_module._clean(value, 240) == value
    assert watcher_module._clean(value, 240, redact=True) == "token=<redacted>"


def test_rendered_mode_shows_more_than_240_characters_unless_limit_is_requested(
    watcher_module,
):
    value = "complete-event-" + "x" * 300

    assert watcher_module._clean(value, None) == value
    assert watcher_module._clean(value, 240) == value[:239] + "…"


def test_command_defaults_to_unlimited_rendered_text(watcher_module, monkeypatch):
    observed = {}

    async def watch(_room, _history, limit, *_args):
        observed["limit"] = limit

    monkeypatch.setattr(watcher_module, "_watch", watch)
    monkeypatch.setattr(
        watcher_module.sys,
        "argv",
        [str(WATCHER_PATH), "forge-agent", "--once"],
    )

    assert watcher_module.main() == 0
    assert observed["limit"] is None


@pytest.mark.parametrize("mode", ["raw", "json"])
def test_redaction_applies_to_raw_and_json_modes(watcher_module, capsys, mode):
    message = {
        "sent_at": 1_788_342_432_000,
        "sender_kind": "agent",
        "sender_agent_name": "lens",
        "body": "token=hidden-value",
    }

    watcher_module._render(message, None, mode, redact=True)

    output = capsys.readouterr().out
    assert "hidden-value" not in output
    assert "token=<redacted>" in output


def test_rendered_mode_sanitizes_terminal_controls_without_changing_raw_mode(watcher_module, capsys):
    body = "diagnostic \x1b[31mred\x1b[0m"
    message = {
        "sent_at": 1_788_342_432_000,
        "sender_kind": "agent",
        "sender_agent_name": "lens",
        "body": body,
    }

    watcher_module._render(message, 240)
    rendered = capsys.readouterr().out
    assert "\x1b" not in rendered
    assert "diagnostic ?red?" in rendered

    watcher_module._render(message, 240, "raw")
    assert capsys.readouterr().out.splitlines()[-1] == body


def test_unknown_events_are_opt_in(watcher_module, capsys):
    message = {
        "sent_at": 1_788_342_432_000,
        "sender_kind": "agent",
        "sender_agent_name": "lens",
        "body": '{"type":"future.event","value":1}',
    }

    watcher_module._render(message, 240)
    assert capsys.readouterr().out == ""

    watcher_module._render(message, 240, show_unknown=True)
    assert "future.event" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("event", "label", "text"),
    [
        ({"type": "safeyolo.supervisor", "event": "started", "pid": 42}, "SUPERV", "started pid=42"),
        ({"type": "safeyolo.supervisor", "event": "signal", "signal": "SIGTERM"}, "SUPERV", "signal signal=SIGTERM"),
        (
            {"type": "safeyolo.supervisor", "event": "crashed", "error_type": "RuntimeError"},
            "ERROR",
            "crashed error_type=RuntimeError",
        ),
        ({"type": "safeyolo.codex.stderr", "text": "provider diagnostic"}, "STDERR", "provider diagnostic"),
    ],
)
def test_renders_supervisor_and_stderr_events(watcher_module, event, label, text):
    assert watcher_module._event_line(event, 240) == (label, text)


def test_renders_supervisor_recovery_fields(watcher_module):
    assert watcher_module._event_line(
        {
            "type": "safeyolo.supervisor",
            "event": "error",
            "status": "retrying",
            "path": "/home/agent/.safeyolo/checkpoint.json",
            "retry_after": 5,
        },
        None,
    ) == (
        "ERROR",
        "error status=retrying path=/home/agent/.safeyolo/checkpoint.json retry_after=5",
    )


def test_renders_oversize_command_with_explicit_middle_snip(watcher_module):
    label, text = watcher_module._event_line(
        {
            "type": "safeyolo.codex.oversize",
            "original_type": "item.completed",
            "original_bytes": 300000,
            "omitted_middle_bytes": 38000,
            "sha256": "a" * 64,
            "summary": {
                "type": "command_execution",
                "command": "rg -n broad-search",
            },
            "head": "first bytes",
            "tail": "last bytes",
        },
        240,
    )

    assert label == "TOOL"
    assert "completed command rg -n broad-search" in text
    assert "middle snipped" in text
    assert "original_bytes=300000" in text
    assert "omitted_bytes=38000" in text
    assert "sha256=" + "a" * 64 in text


@pytest.mark.asyncio
async def test_nats_loss_is_visible_and_retries_from_the_same_cursor(
    watcher_module,
    monkeypatch,
    capsys,
):
    waits = []

    async def read_room(*_args, **_kwargs):
        return {"messages": [], "next_cursor": 7, "has_more": False}

    async def wait_for_message(*_args, **kwargs):
        waits.append(kwargs["since_sequence"])
        if len(waits) == 1:
            raise watcher_module.NatsUnavailable("connection refused")
        raise asyncio.CancelledError

    async def no_delay(_seconds):
        return None

    monkeypatch.setattr(watcher_module.api, "read_room", read_room)
    monkeypatch.setattr(watcher_module.api, "wait_for_message", wait_for_message)
    monkeypatch.setattr(watcher_module.asyncio, "sleep", no_delay)

    with pytest.raises(asyncio.CancelledError):
        await watcher_module._watch(
            "lens-agent",
            0,
            240,
            "rendered",
            False,
            False,
            False,
            False,
        )

    assert waits == [7, 7]
    output = capsys.readouterr().out
    assert "CONN    lost NATS unavailable; cursor=7 retrying in 1s" in output


@pytest.mark.asyncio
async def test_history_pages_to_the_current_tail(watcher_module, monkeypatch, capsys):
    calls = []

    def message(sequence):
        return {
            "sequence": sequence,
            "sent_at": 1_788_342_432_000 + sequence,
            "sender_kind": "agent",
            "sender_agent_name": "lens",
            "body": json.dumps(
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": f"message-{sequence}"},
                }
            ),
        }

    async def read_room(*_args, **kwargs):
        cursor = kwargs["since_sequence"]
        calls.append(cursor)
        if cursor == 0:
            return {
                "messages": [message(1), message(2)],
                "next_cursor": 2,
                "has_more": True,
            }
        return {
            "messages": [message(3), message(4)],
            "next_cursor": 4,
            "has_more": False,
        }

    monkeypatch.setattr(watcher_module.api, "read_room", read_room)

    await watcher_module._watch(
        "lens-agent",
        2,
        None,
        "rendered",
        False,
        False,
        False,
        True,
    )

    assert calls == [0, 2]
    output = capsys.readouterr().out
    assert "message-1" not in output
    assert "message-2" not in output
    assert "message-3" in output
    assert "message-4" in output
