"""Focused CLI and watch contracts for coordination Stage 0."""

from __future__ import annotations

import asyncio
import io
import json

from rich.console import Console
from typer.testing import CliRunner

from safeyolo.commands import coord, watch
from safeyolo.core.audit_schema import AuditEvent, EventKind, Severity


def test_room_create_uses_distinct_internal_grant_operation_ids(monkeypatch):
    captured: list[str] = []
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(coord, "_run", lambda _coro: "rm-test")
    monkeypatch.setattr(coord.api, "create_room", lambda _name: object())
    monkeypatch.setattr(coord, "_resolve_agent_id", lambda name: f"ag-{name}")

    def grant(*_args, operation_id, **_kwargs):
        captured.append(operation_id)

    monkeypatch.setattr(coord.api, "grant", grant)
    result = CliRunner().invoke(
        coord.coord_app,
        ["room", "create", "r", "--member", "alice", "--member", "bob"],
    )
    assert result.exit_code == 0, result.output
    assert len(captured) == 3
    assert len(set(captured)) == 3
    assert all(value.startswith("op-") for value in captured)
    assert "operation_id" not in result.output


def test_grant_accepts_and_prints_caller_operation_id(monkeypatch):
    seen = {}
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(coord, "_resolve_agent_id", lambda _name: "ag-alice")

    def grant(*_args, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(coord.api, "grant", grant)
    result = CliRunner().invoke(
        coord.coord_app,
        ["grant", "r", "alice", "--operation-id", "client-retry-7"],
    )
    assert result.exit_code == 0, result.output
    assert seen["operation_id"] == "client-retry-7"
    assert "operation_id=client-retry-7" in result.output


def test_revoke_generates_and_prints_operation_id(monkeypatch):
    seen = {}
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(coord, "_resolve_agent_id", lambda _name: "ag-alice")

    def revoke(*_args, **kwargs):
        seen.update(kwargs)
        return True

    monkeypatch.setattr(coord.api, "revoke_grant", revoke)
    result = CliRunner().invoke(coord.coord_app, ["revoke", "r", "alice"])
    assert result.exit_code == 0, result.output
    assert seen["operation_id"].startswith("op-")
    assert f"operation_id={seen['operation_id']}" in result.output


def test_create_room_and_send_do_not_claim_operation_id_support():
    import inspect

    assert "operation_id" not in inspect.signature(coord.api.create_room).parameters
    assert "operation_id" not in inspect.signature(coord.api.send).parameters


def test_interactive_send_reports_ambiguous_acceptance_without_safe_retry(
    monkeypatch,
):
    output = io.StringIO()
    monkeypatch.setattr(
        coord,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )
    inputs = iter(["possibly accepted", ":q"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(inputs))

    async def ambiguous_send(*_args, **_kwargs):
        raise coord.NatsPublishOutcomeUnknown("PubAck connection closed")

    monkeypatch.setattr(coord.api, "send", ambiguous_send)

    class Runtime:
        def run(self, coroutine):
            return asyncio.run(coroutine)

    coord._interactive_loop(Runtime(), "r", 0)
    rendered = output.getvalue()
    normalized = " ".join(rendered.split())
    assert "message acceptance is UNKNOWN" in normalized
    assert "JetStream may have accepted it" in normalized
    assert "no caller-visible send idempotency" in normalized
    assert "NOT sent" not in rendered
    assert "message was not accepted" not in rendered


def test_watch_accepts_coord_event_and_deduplicates_event_id(capsys):
    watch._seen_event_ids.clear()
    watch._seen_event_id_set.clear()
    watch._drift_warnings_emitted = 0
    event = AuditEvent(
        event_id="evt-dedup",
        event="coord.grant_changed",
        kind=EventKind.COORD,
        severity=Severity.LOW,
        summary="Coord room grant changed",
        details={"room_id": "rm-r"},
    )
    line = json.dumps(event.to_jsonl())
    assert watch._parse_jsonl_line(line) == event.to_jsonl()
    assert watch._parse_jsonl_line(line) is None
    assert "schema drift" not in capsys.readouterr().out
