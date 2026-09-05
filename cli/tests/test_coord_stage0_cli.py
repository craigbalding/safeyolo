"""Focused CLI and watch contracts for coordination Stage 0."""

from __future__ import annotations

import asyncio
import io
import json
import os
import pty
import select
import subprocess
import sys

import pytest
from rich.console import Console
from typer.testing import CliRunner

from safeyolo.commands import coord, watch
from safeyolo.core.audit_schema import AuditEvent, EventKind, Severity


def test_main_cli_import_does_not_load_prompt_toolkit():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import safeyolo.cli; "
            "assert 'prompt_toolkit' not in sys.modules",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


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


def test_brief_set_requires_expected_revision_and_passes_operation_id(monkeypatch):
    seen = {}
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(coord, "_run", lambda result: result)

    def set_brief(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return {
            "revision": 5,
            "content_hash": "a" * 64,
        }

    monkeypatch.setattr(coord.api, "set_brief", set_brief)
    missing = CliRunner().invoke(
        coord.coord_app,
        ["brief", "set", "r", "# intent"],
    )
    assert missing.exit_code != 0

    result = CliRunner().invoke(
        coord.coord_app,
        [
            "brief",
            "set",
            "r",
            "# intent",
            "--expected-revision",
            "4",
            "--operation-id",
            "op-brief-5",
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen == {
        "args": ("r", "# intent"),
        "kwargs": {
            "expected_revision": 4,
            "operation_id": "op-brief-5",
        },
    }
    assert "revision=5" in result.output
    assert "operation_id=op-brief-5" in result.output


def test_brief_set_file_and_text_are_mutually_exclusive(monkeypatch, tmp_path):
    markdown = tmp_path / "brief.md"
    markdown.write_text("# from file\n")
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")

    result = CliRunner().invoke(
        coord.coord_app,
        [
            "brief",
            "set",
            "r",
            "inline",
            "--file",
            str(markdown),
            "--expected-revision",
            "0",
        ],
    )
    assert result.exit_code == 1
    assert "exactly one" in result.output


def test_brief_show_json_exposes_current_trusted_state(monkeypatch):
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(
        coord.api,
        "show_brief",
        lambda *_args, **_kwargs: {
            "room_id": "rm-r",
            "object_id": "brief-r",
            "revision": 3,
            "markdown": "# trusted",
            "content_hash": "b" * 64,
            "updated_at": 1,
        },
    )

    result = CliRunner().invoke(
        coord.coord_app,
        ["brief", "show", "r", "--json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["markdown"] == "# trusted"


def test_room_state_json_calls_operator_inventory_surface(monkeypatch):
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(coord, "_run", lambda result: result)
    state = {
        "room_id": "rm-r",
        "room_name": "r",
        "origin_instance_id": "sy-test",
        "generated_at": 1,
        "brief": {"revision": 0},
        "members": [],
        "resource_leases": [],
    }
    monkeypatch.setattr(coord.api, "get_room_state", lambda room: state)

    result = CliRunner().invoke(coord.coord_app, ["state", "r", "--json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == state


def test_inventory_capability_advertisement_passes_stable_agent_id_and_operation(
    monkeypatch,
):
    seen = {}
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(
        coord,
        "_resolve_agent_id",
        lambda name: "ag-" + "a" * 32,
    )

    def advertise(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return {"changed": True}

    monkeypatch.setattr(coord.api, "advertise_capability", advertise)
    result = CliRunner().invoke(
        coord.coord_app,
        [
            "inventory",
            "advertise-capability",
            "r",
            "alice",
            "rundeck:acceptance_runner",
            "--operation-id",
            "op-ad",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == {
        "args": ("r", "ag-" + "a" * 32, "rundeck:acceptance_runner"),
        "kwargs": {"advertised": True, "operation_id": "op-ad"},
    }
    assert "operation_id=op-ad" in result.output


def test_inventory_resource_unadvertisement_uses_operator_surface(monkeypatch):
    seen = {}
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")

    def advertise(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        return {"changed": True}

    monkeypatch.setattr(coord.api, "advertise_resource", advertise)
    result = CliRunner().invoke(
        coord.coord_app,
        [
            "inventory",
            "unadvertise-resource",
            "r",
            "rundeck",
            "devstack",
            "--operation-id",
            "op-resource",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == {
        "args": ("r", "rundeck", "devstack"),
        "kwargs": {"advertised": False, "operation_id": "op-resource"},
    }


def _set_chat_inputs(monkeypatch, *lines):
    inputs = iter(lines)

    class PromptSession:
        async def prompt_async(self, _prompt):
            return next(inputs)

    async def receive_messages(*_args, **_kwargs):
        await asyncio.Future()

    monkeypatch.setattr("prompt_toolkit.PromptSession", PromptSession)
    monkeypatch.setattr(coord, "_receive_messages", receive_messages)


def test_interactive_send_reports_ambiguous_acceptance_without_safe_retry(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(
        coord,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )
    _set_chat_inputs(monkeypatch, "possibly accepted", ":q")

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


def test_interactive_send_uses_explicit_target(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(
        coord,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )
    _set_chat_inputs(monkeypatch, "targeted direction", ":q")
    seen = []

    async def send(*_args, **kwargs):
        seen.append(kwargs["notify"])
        return {
            "attention_status": "ready",
            "attention_intent": {"mode": "targeted"},
        }

    async def read_room(*_args, **_kwargs):
        return {"messages": [], "next_cursor": 0, "has_more": False}

    monkeypatch.setattr(coord.api, "send", send)
    monkeypatch.setattr(coord.api, "read_room", read_room)

    class Runtime:
        def run(self, coroutine):
            return asyncio.run(coroutine)

    coord._interactive_loop(Runtime(), "r", 0, target="relay")
    assert seen == [["relay"]]
    assert "attention=targeted target=relay" in output.getvalue()


def _install_coord_send_stub(monkeypatch, result=None, error=None):
    seen = {}

    async def send(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        if error is not None:
            raise error
        return result or {
            "attention_status": "ready",
            "attention_intent": {"mode": "room"},
        }

    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    monkeypatch.setattr(coord.api, "send", send)
    monkeypatch.setattr(coord, "_run", lambda coroutine: asyncio.run(coroutine))
    return seen


def test_noninteractive_send_uses_trusted_operator_and_multiple_targets(monkeypatch):
    seen = _install_coord_send_stub(
        monkeypatch,
        result={
            "attention_status": "ready",
            "attention_intent": {"mode": "targeted"},
        },
    )

    result = CliRunner().invoke(
        coord.coord_app,
        [
            "send",
            "backlog",
            "operator direction",
            "--to",
            "relay",
            "--to",
            "lens",
            "--content-type",
            "text/plain",
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen == {
        "args": ("backlog", "operator", None, "operator direction"),
        "kwargs": {"declared_content_type": "text/plain", "notify": ["relay", "lens"]},
    }
    assert "message accepted" in result.output
    assert "attention=targeted" in result.output
    assert "targets=relay,lens" in result.output


def test_noninteractive_send_reads_file_and_preserves_trailing_newline(
    monkeypatch, tmp_path
):
    message = tmp_path / "direction.md"
    message.write_text("from file\n", encoding="utf-8")
    seen = _install_coord_send_stub(monkeypatch)

    result = CliRunner().invoke(
        coord.coord_app,
        ["send", "backlog", "--file", str(message)],
    )

    assert result.exit_code == 0, result.output
    assert seen["args"] == ("backlog", "operator", None, "from file\n")
    assert seen["kwargs"]["notify"] == "room"


def test_noninteractive_send_reads_explicit_stdin(monkeypatch):
    seen = _install_coord_send_stub(monkeypatch)

    result = CliRunner().invoke(
        coord.coord_app,
        ["send", "backlog", "--stdin", "--to", "relay"],
        input="from stdin\n",
    )

    assert result.exit_code == 0, result.output
    assert seen["args"] == ("backlog", "operator", None, "from stdin\n")
    assert seen["kwargs"]["notify"] == ["relay"]


def test_noninteractive_send_stdin_decodes_utf8_bytes_independent_of_stream_encoding(
    monkeypatch,
):
    stream = io.TextIOWrapper(
        io.BytesIO("caf\N{LATIN SMALL LETTER E WITH ACUTE}\n".encode()),
        encoding="latin-1",
    )
    monkeypatch.setattr(coord.sys, "stdin", stream)

    assert coord._read_send_body(None, None, True) == "caf\N{LATIN SMALL LETTER E WITH ACUTE}\n"


def test_noninteractive_send_rejects_invalid_utf8_stdin_bytes(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(
        coord,
        "console",
        Console(file=output, force_terminal=False, color_system=None),
    )
    stream = io.TextIOWrapper(io.BytesIO(b"caf\xe9\n"), encoding="latin-1")
    monkeypatch.setattr(coord.sys, "stdin", stream)

    with pytest.raises(coord.typer.Exit):
        coord._read_send_body(None, None, True)

    assert "could not read message from stdin: UnicodeDecodeError" in output.getvalue()


@pytest.mark.parametrize(
    "args",
    [
        ["send", "backlog"],
        ["send", "backlog", "inline", "--stdin"],
        ["send", "backlog", "inline", "--file", "message.md"],
    ],
)
def test_noninteractive_send_requires_exactly_one_body_source(args, tmp_path):
    message = tmp_path / "message.md"
    message.write_text("file body", encoding="utf-8")
    args = [str(message) if value == "message.md" else value for value in args]

    result = CliRunner().invoke(coord.coord_app, args, input="stdin body")

    assert result.exit_code == 1
    assert "provide exactly one of TEXT, --file, or --stdin" in result.output


@pytest.mark.parametrize(
    ("args", "input"),
    [
        (["send", "backlog", ""], ""),
        (["send", "backlog", "   "], ""),
        (["send", "backlog", "--stdin"], " \n\t"),
    ],
)
def test_noninteractive_send_rejects_empty_body(args, input):
    result = CliRunner().invoke(coord.coord_app, args, input=input)

    assert result.exit_code == 1
    assert "message body must be non-empty" in result.output


def test_noninteractive_send_reports_invalid_target_without_sending(monkeypatch):
    error = coord.api.attention.AttentionTargetError(
        "one or more notify targets are not active room members"
    )
    _install_coord_send_stub(monkeypatch, error=error)

    result = CliRunner().invoke(
        coord.coord_app,
        ["send", "backlog", "direction", "--to", "revoked-agent"],
    )

    assert result.exit_code == 1
    assert "not active room members" in result.output


def test_noninteractive_send_reports_authorization_and_provider_errors(monkeypatch):
    for error, expected in (
        (coord.api.GrantError("permission 'send' denied"), "send' denied"),
        (coord.api.NotFoundError("room 'missing' not found"), "not found"),
        (coord.NatsUnavailable("connection refused"), "coord runtime unreachable"),
    ):
        _install_coord_send_stub(monkeypatch, error=error)
        result = CliRunner().invoke(
            coord.coord_app,
            ["send", "backlog", "direction"],
        )
        assert result.exit_code == 1
        assert expected in result.output
        if isinstance(error, coord.NatsUnavailable):
            assert "message was not accepted; it was not sent" in result.output


def test_approved_factory_coordinator_resolution_is_room_scoped(monkeypatch, tmp_path):
    factories = tmp_path / "factories"
    (factories / "backlog").mkdir(parents=True)
    (factories / "backlog" / "approved").write_text("snapshot\n")
    (factories / "other").mkdir()
    (factories / "other" / "approved").write_text("snapshot\n")
    monkeypatch.setattr(coord, "factories_dir", lambda: factories)

    def load(name):
        room = "backlog" if name == "backlog" else "other"
        return "id", tmp_path / name, {
            "room": room,
            "operator_input": {"to": "coordinator"},
            "roles": {"coordinator": {"agent": "navigator"}},
        }

    monkeypatch.setattr(coord, "load_approved_snapshot", load)

    assert coord._approved_factory_coordinator("backlog") == "navigator"
    assert coord._approved_factory_coordinator("unconfigured") is None


def test_approved_factory_coordinator_ambiguity_fails_closed(monkeypatch, tmp_path):
    factories = tmp_path / "factories"
    for name in ("one", "two"):
        (factories / name).mkdir(parents=True)
        (factories / name / "approved").write_text("snapshot\n")
    monkeypatch.setattr(coord, "factories_dir", lambda: factories)

    def load(name):
        return "id", tmp_path / name, {
            "room": "backlog",
            "operator_input": {"to": "coordinator"},
            "roles": {"coordinator": {"agent": f"relay-{name}"}},
        }

    monkeypatch.setattr(coord, "load_approved_snapshot", load)

    with pytest.raises(coord.FactoryContractError, match="multiple approved"):
        coord._approved_factory_coordinator("backlog")


def test_chat_rejects_target_in_observe_mode(monkeypatch):
    monkeypatch.setattr(coord.api, "bootstrap", lambda: "sy-test")
    result = CliRunner().invoke(
        coord.coord_app,
        ["chat", "r", "--observe", "--to", "relay"],
    )
    assert result.exit_code == 1
    assert "--to requires interactive mode" in result.output


def test_chat_rejects_piped_interactive_input_without_terminal_controls():
    """Piped input must fail before prompt-toolkit can emit cursor queries."""
    code = (
        "import sys; from safeyolo.cli import app; "
        "sys.argv = ['safeyolo', 'coord', 'chat', 'piped-room']; app()"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        input="operator direction\n",
        capture_output=True,
        text=True,
        env={**os.environ, "SAFEYOLO_ALLOW_ROOT": "1"},
        check=False,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 2, output
    assert "interactive coord chat requires a terminal on stdin" in output
    assert "piped input is not accepted" in output
    assert "--observe" in output
    assert "\x1b" not in output
    assert ";1R" not in output


def test_chat_rejects_piped_stdin_with_terminal_stdout():
    """The stdin pipe case is safe even when output is a real terminal."""
    code = (
        "import sys; from safeyolo.cli import app; "
        "sys.argv = ['safeyolo', 'coord', 'chat', 'piped-room']; app()"
    )
    master_fd, slave_fd = pty.openpty()
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            stdin=subprocess.PIPE,
            stdout=slave_fd,
            stderr=slave_fd,
            env={**os.environ, "SAFEYOLO_ALLOW_ROOT": "1"},
        )
    finally:
        os.close(slave_fd)

    assert process.stdin is not None
    process.stdin.write(b"operator direction\n")
    process.stdin.close()
    process.wait(timeout=10)

    output = bytearray()
    while True:
        readable, _, _ = select.select([master_fd], [], [], 1.0)
        if not readable:
            break
        try:
            chunk = os.read(master_fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        output.extend(chunk)
    os.close(master_fd)

    rendered = bytes(output).decode("utf-8", errors="replace")
    assert process.returncode == 2, rendered
    assert "interactive coord chat requires a terminal on stdin" in rendered
    assert "\x1b" not in rendered
    assert ";1R" not in rendered


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
