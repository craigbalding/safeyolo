"""Tests for the bounded guest-side Codex coord supervisor."""

from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR_PATH = REPO_ROOT / "contrib/codex-coord-supervisor.py"


@pytest.fixture(scope="module")
def supervisor_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("codex_coord_supervisor", SUPERVISOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _config(module: ModuleType, tmp_path: Path, **overrides):
    values = {
        "agent_name": "forge",
        "rooms": ("backlog",),
        "coordinators": frozenset({"relay"}),
        "workspace": str(tmp_path),
        "wait_seconds": 5,
        "page_limit": 16,
        "startup_timeout_seconds": 30,
        "work_timeout_seconds": 30,
        "completion_grace_seconds": 5,
        "terminate_grace_seconds": 1,
        "backoff_initial_seconds": 2,
        "backoff_max_seconds": 10,
    }
    values.update(overrides)
    return module.Config(**values)


def _resolved(
    attention_id: str,
    *,
    sender: str = "relay",
    body: str = "TASK task=one assignee=forge",
    room_id: str = "room-1",
):
    return {
        "edge": {
            "attention_id": attention_id,
            "room_id": room_id,
            "kind": "message",
            "object_id": "message-1",
            "revision_or_sequence": 11,
        },
        "object": {
            "msg_id": "message-1",
            "sender_kind": "agent",
            "sender_agent_id": f"agent-{sender}",
            "sender_agent_name": sender,
            "content_type": "text/plain",
            "body": body,
            "sequence": 11,
        },
    }


def _wait_event(module: ModuleType, state, objects, *, next_cursor=12, status="completed", error=None):
    return {
        "type": "item.completed",
        "item": {
            "type": "mcp_tool_call",
            "server": "safeyolo-coord",
            "tool": "wait_for_coord",
            "arguments": {
                "since_sequence": state["safe_cursor"],
                "timeout_seconds": 5,
                "limit": 16,
            },
            "result": {"structured_content": {"objects": objects, "next_cursor": next_cursor}},
            "error": error,
            "status": status,
        },
    }


def _terminal_event(attention_id: str, *, room_name: str = "backlog", body: str | None = None):
    body = body or f"DONE task=one attention_id={attention_id}\nresult=complete"
    return {
        "type": "item.completed",
        "item": {
            "type": "mcp_tool_call",
            "server": "safeyolo-coord",
            "tool": "send",
            "arguments": {"room_name": room_name, "body": body},
            "result": {
                "structured_content": {
                    "envelope": {
                        "sender_kind": "agent",
                        "sender_agent_id": "agent-forge",
                        "sender_agent_name": "forge",
                        "body": body,
                    },
                    "sequence": 13,
                }
            },
            "error": None,
            "status": "completed",
        },
    }


def test_structured_wait_checkpoints_task_before_terminal(supervisor_module, tmp_path):
    module = supervisor_module
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})
    attention_id = "attn-" + "a" * 32

    consumer.consume(_wait_event(module, state, [_resolved(attention_id)]))

    persisted = module.load_state(state_path)
    assert persisted["safe_cursor"] == 12
    assert persisted["in_flight"][0]["attention_id"] == attention_id
    assert persisted["in_flight"][0]["requires_terminal"] is True

    consumer.consume(_terminal_event(attention_id))
    persisted = module.load_state(state_path)
    assert persisted["in_flight"] == []
    assert persisted["recent_attention_ids"] == [attention_id]


def test_empty_wait_is_idle_only_from_structured_success(supervisor_module, tmp_path):
    module = supervisor_module
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [], next_cursor=0))

    assert consumer.result.wait_succeeded is True
    assert consumer.result.wait_was_empty is True
    assert module.load_state(state_path)["safe_cursor"] == 0


@pytest.mark.parametrize(
    "event_change",
    [
        {"status": "failed", "error": {"message": "coord unavailable"}},
        {"status": "completed", "error": None, "next_cursor": -1},
    ],
)
def test_failed_or_invalid_wait_never_advances_cursor(supervisor_module, tmp_path, event_change):
    module = supervisor_module
    state = module.empty_state()
    state["safe_cursor"] = 7
    state_path = tmp_path / "state.json"
    module.save_state(state_path, state)
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})
    event = _wait_event(
        module,
        state,
        [],
        next_cursor=event_change.get("next_cursor", 8),
        status=event_change["status"],
        error=event_change["error"],
    )

    consumer.consume(event)

    assert consumer.result.wait_succeeded is False
    assert consumer.result.wait_failed is True
    assert module.load_state(state_path)["safe_cursor"] == 7


def test_replayed_attention_is_deduplicated(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "b" * 32
    state = module.empty_state()
    state["recent_attention_ids"] = [attention_id]
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [_resolved(attention_id)]))
    consumer.consume({"type": "turn.completed"})

    persisted = module.load_state(state_path)
    assert persisted["safe_cursor"] == 12
    assert persisted["in_flight"] == []
    assert persisted["recent_attention_ids"] == [attention_id]


def test_peer_task_is_not_promoted_to_authorized_work(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "c" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [_resolved(attention_id, sender="peer")]))
    assert state["in_flight"][0]["requires_terminal"] is False
    consumer.consume({"type": "turn.completed"})

    assert module.load_state(state_path)["in_flight"] == []


@pytest.mark.parametrize(
    "body",
    [
        "TASK task=one assignee=lens",
        "TASK task=one",
        "TASK task=one assignee=forge assignee=forge",
    ],
)
def test_task_for_another_or_ambiguous_assignee_is_not_promoted(supervisor_module, tmp_path, body):
    module = supervisor_module
    attention_id = "attn-" + "8" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [_resolved(attention_id, body=body)]))

    assert state["in_flight"][0]["requires_terminal"] is False


def test_attention_from_unconfigured_room_is_checkpointed_and_ignored(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "7" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, room_id="authorized-extra-room")],
        )
    )

    persisted = module.load_state(state_path)
    assert consumer.result.wait_succeeded is True
    assert persisted["safe_cursor"] == 12
    assert persisted["in_flight"] == []
    assert persisted["recent_attention_ids"] == [attention_id]

    prompt = module.build_prompt(_config(module, tmp_path), module.empty_state(), {"room-1": "backlog"})
    assert "Ignore returned objects whose edge.room_id" in prompt
    assert '"configured_room_ids":{"room-1":"backlog"}' in prompt


def test_canonical_history_recovers_terminal_lost_after_send(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    attention_id = "attn-" + "d" * 32
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": attention_id,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": "TASK task=one assignee=forge",
            "requires_terminal": True,
        }
    ]
    monkeypatch.setattr(
        module,
        "_history_page",
        lambda room, since: {
            "messages": [
                {
                    "sender_kind": "agent",
                    "sender_agent_id": "agent-forge",
                    "sender_agent_name": "forge",
                    "body": f"DONE task=one attention_id={attention_id}",
                }
            ],
            "next_cursor": 12,
            "has_more": False,
        },
    )

    assert module.reconcile_terminals(_config(module, tmp_path), state) is True
    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


def test_terminal_requires_exact_attention_id(supervisor_module):
    module = supervisor_module
    pending = {
        "attention_id": "attn-" + "1" * 32,
        "body": "TASK issue=#471 task=first assignee=forge",
    }

    assert module._terminal_matches(pending, "DONE issue=#471 task=first") is False
    assert module._terminal_matches(pending, "DONE issue=#471 task=second") is False
    assert (
        module._terminal_matches(
            pending,
            f"DONE issue=#471 task=first attention_id={'attn-' + '2' * 32}",
        )
        is False
    )
    assert (
        module._terminal_matches(
            pending,
            f"DONE issue=#471 task=other attention_id={'attn-' + '1' * 32}",
        )
        is True
    )


def test_terminal_send_must_target_pending_room(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "6" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _config(module, tmp_path, rooms=("backlog", "other")),
        state,
        state_path,
        {"room-1": "backlog", "room-2": "other"},
    )
    consumer.consume(_wait_event(module, state, [_resolved(attention_id)]))

    consumer.consume(_terminal_event(attention_id, room_name="other"))
    assert module.load_state(state_path)["in_flight"][0]["attention_id"] == attention_id
    assert consumer.result.terminal_observed is False

    consumer.consume(_terminal_event(attention_id))
    assert module.load_state(state_path)["in_flight"] == []
    assert consumer.result.terminal_observed is True


def test_one_correlation_label_cannot_complete_two_attentions(supervisor_module, tmp_path):
    module = supervisor_module
    first = "attn-" + "4" * 32
    second = "attn-" + "5" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})
    consumer.consume(_wait_event(module, state, [_resolved(first), _resolved(second)], next_cursor=13))

    consumer.consume(_terminal_event(first, body="DONE task=one\nresult=complete"))

    assert {item["attention_id"] for item in module.load_state(state_path)["in_flight"]} == {
        first,
        second,
    }


def test_recovery_prompt_uses_checkpoint_and_skips_wait(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "e" * 32
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": attention_id,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": "TASK task=one assignee=forge",
            "requires_terminal": True,
        }
    ]

    prompt = module.build_prompt(_config(module, tmp_path), state, {"room-1": "backlog"})

    assert "Do not call wait_for_coord in this turn" in prompt
    assert attention_id in prompt
    assert "attention_id=<id>" in prompt
    assert '"configured_room_ids":{"room-1":"backlog"}' in prompt

    state_path = tmp_path / "state.json"
    module.save_state(state_path, state)
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})
    consumer.consume(_wait_event(module, state, [], next_cursor=12))
    assert consumer.result.wait_failed is True
    assert module.load_state(state_path)["safe_cursor"] == 0


@pytest.mark.parametrize("saw_turn_started", [False, True])
def test_unavailable_resume_preserves_work_and_starts_fresh_next(
    supervisor_module, tmp_path, monkeypatch, saw_turn_started
):
    module = supervisor_module
    attention_id = "attn-" + "f" * 32
    state_path = tmp_path / "state.json"
    state = module.empty_state()
    state["thread_id"] = "missing-thread"
    state["in_flight"] = [
        {
            "attention_id": attention_id,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": "TASK task=one assignee=forge",
            "requires_terminal": True,
        }
    ]
    module.save_state(state_path, state)
    monkeypatch.setattr(module, "preflight", lambda config: {"room-1": "backlog"})
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)
    monkeypatch.setattr(
        module,
        "run_invocation",
        lambda *args: module.InvocationResult(saw_turn_started=saw_turn_started),
    )
    supervisor = module.Supervisor(_config(module, tmp_path), state_path, [])

    assert supervisor.cycle() is False
    persisted = module.load_state(state_path)
    assert persisted["thread_id"] is None
    assert persisted["in_flight"][0]["attention_id"] == attention_id


def test_exit_zero_without_structured_wait_is_not_idle(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    state_path = tmp_path / "state.json"
    module.save_state(state_path, module.empty_state())
    monkeypatch.setattr(module, "preflight", lambda config: {"room-1": "backlog"})
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)
    monkeypatch.setattr(
        module,
        "run_invocation",
        lambda *args: module.InvocationResult(
            saw_turn_started=True,
            saw_turn_completed=True,
        ),
    )
    supervisor = module.Supervisor(_config(module, tmp_path), state_path, [])

    assert supervisor.cycle() is False
    assert module.load_state(state_path)["consecutive_failures"] == 1


def test_backoff_is_exponential_and_bounded(supervisor_module, tmp_path):
    module = supervisor_module
    state_path = tmp_path / "state.json"
    module.save_state(state_path, module.empty_state())
    supervisor = module.Supervisor(_config(module, tmp_path), state_path, [])

    observed = []
    for failures in range(1, 7):
        supervisor.state["consecutive_failures"] = failures
        observed.append(supervisor.backoff_seconds())

    assert observed == [2, 4, 8, 10, 10, 10]


def test_atomic_checkpoint_is_private_and_bounded(supervisor_module, tmp_path):
    module = supervisor_module
    state_path = tmp_path / "state.json"
    state = module.empty_state()
    state["recent_attention_ids"] = [
        "attn-" + f"{number:032x}" for number in range(module.MAX_RECENT_ATTENTION_IDS + 1)
    ]

    module.save_state(state_path, module.empty_state())
    assert state_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(module.SupervisorError, match="deduplication"):
        module.load_state(_write_json(tmp_path / "oversized-list.json", state))


def test_checkpoint_rejects_unknown_fields(supervisor_module, tmp_path):
    module = supervisor_module
    state = module.empty_state()
    state["OPENAI_API_KEY"] = "must-not-persist"

    with pytest.raises(module.SupervisorError, match="unsupported schema"):
        module.load_state(_write_json(tmp_path / "secret-state.json", state))


def _stage_preflight(monkeypatch, module, tmp_path, *, tool_timeout=330, login="Logged in using ChatGPT"):
    codex_home = tmp_path / "codex-home"
    launcher = tmp_path / "coord-launcher"
    codex_home.mkdir()
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    (codex_home / "config.toml").write_text(
        f'[mcp_servers.safeyolo-coord]\ncommand = "{launcher}"\ntool_timeout_sec = {tool_timeout}\n'
    )
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: module.subprocess.CompletedProcess(args[0], 0, login, ""),
    )


def test_preflight_requires_chatgpt_subscription(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path, login="Logged in using an API key")
    monkeypatch.setattr(module, "_api_json", lambda *args, **kwargs: {"agent_api": "ok"})

    with pytest.raises(module.SupervisorError, match="ChatGPT subscription"):
        module.preflight(_config(module, tmp_path))


def test_preflight_requires_mcp_timeout_above_wait(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path, tool_timeout=5)
    monkeypatch.setattr(module, "_api_json", lambda *args, **kwargs: {"agent_api": "ok"})

    with pytest.raises(module.SupervisorError, match="MCP timeout"):
        module.preflight(_config(module, tmp_path))


def test_preflight_requires_room_receive_authority(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path)

    def api(path, **kwargs):
        if path == "/health":
            return {"agent_api": "ok"}
        return {"room_id": "room-1", "permissions": ["send"]}

    monkeypatch.setattr(module, "_api_json", api)

    with pytest.raises(module.SupervisorError, match="receive permission"):
        module.preflight(_config(module, tmp_path))


def _write_json(path: Path, value) -> Path:
    path.write_text(json.dumps(value))
    return path


def test_timeout_cleans_the_owned_process_group(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    fake_codex = tmp_path / "fake-codex"
    child_pid_file = tmp_path / "child.pid"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, subprocess, time\n"
        "from pathlib import Path\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-one'}), flush=True)\n"
        "print(json.dumps({'type':'turn.started'}), flush=True)\n"
        "child = subprocess.Popen(['sleep', '60'], start_new_session=True)\n"
        "Path(os.environ['TEST_CHILD_PID']).write_text(str(child.pid))\n"
        "time.sleep(60)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    monkeypatch.setenv("TEST_CHILD_PID", str(child_pid_file))
    state = module.empty_state()
    state_path = tmp_path / "state.json"

    result = module.run_invocation(
        _config(module, tmp_path, startup_timeout_seconds=1),
        state,
        state_path,
        {"room-1": "backlog"},
        [],
    )

    assert result.timed_out is True
    child_pid = int(child_pid_file.read_text())
    for _ in range(50):
        if not Path(f"/proc/{child_pid}").exists():
            break
        time.sleep(0.02)
    assert not Path(f"/proc/{child_pid}").exists()


def test_work_deadline_does_not_slide_on_later_stdout(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    fake_codex = tmp_path / "noisy-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json, time\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-one'}), flush=True)\n"
        "print(json.dumps({'type':'turn.started'}), flush=True)\n"
        "print(json.dumps({\n"
        "  'type':'item.completed',\n"
        "  'item':{\n"
        "    'type':'mcp_tool_call',\n"
        "    'server':'safeyolo-coord',\n"
        "    'tool':'wait_for_coord',\n"
        "    'arguments':{'since_sequence':0,'timeout_seconds':5,'limit':16},\n"
        "    'result':{'structured_content':{'objects':[{\n"
        "      'edge':{'attention_id':'attn-' + '3' * 32,'room_id':'room-1',\n"
        "              'kind':'message','object_id':'message-1','revision_or_sequence':1},\n"
        "      'object':{'sender_agent_id':'agent-relay','sender_agent_name':'relay',\n"
        "                'body':'TASK task=one assignee=forge','sequence':1}\n"
        "    }],'next_cursor':1}},\n"
        "    'error':None,\n"
        "    'status':'completed'\n"
        "  }\n"
        "}), flush=True)\n"
        "for _ in range(20):\n"
        "    time.sleep(0.2)\n"
        "    print(json.dumps({'type':'benign.progress'}), flush=True)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    state = module.empty_state()
    state_path = tmp_path / "state.json"

    started = time.monotonic()
    result = module.run_invocation(
        _config(
            module,
            tmp_path,
            startup_timeout_seconds=10,
            work_timeout_seconds=1,
        ),
        state,
        state_path,
        {"room-1": "backlog"},
        [],
    )
    elapsed = time.monotonic() - started

    assert result.timed_out is True
    assert elapsed < 2.5


def test_cleanup_never_signals_reused_process_group(supervisor_module, monkeypatch):
    module = supervisor_module

    class ReapedProcess:
        pid = 4242
        returncode = None

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def wait(timeout=None):
            return 0

    group_signals = []
    monkeypatch.setattr(module, "_process_start_time", lambda pid: "new-unrelated-start")
    monkeypatch.setattr(
        module.os,
        "killpg",
        lambda pid, signal_number: group_signals.append((pid, signal_number)),
    )

    module._terminate_process_group(ReapedProcess(), 0, "old-owned-start")

    assert group_signals == []


def test_cleanup_signals_only_fingerprint_matching_descendants(supervisor_module, monkeypatch):
    module = supervisor_module

    class ReapedProcess:
        pid = 4242
        returncode = 0

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def wait(timeout=None):
            return 0

    identities = {4242: "new-unrelated-start", 5000: "owned-child-start"}
    individual_signals = []
    group_signals = []

    def process_start_time(pid):
        return identities.get(pid)

    def signal_identity(pid, start_time, signal_number):
        if identities.get(pid) != start_time:
            return False
        individual_signals.append((pid, signal_number))
        identities.pop(pid)
        return True

    monkeypatch.setattr(module, "_process_start_time", process_start_time)
    monkeypatch.setattr(module, "_signal_pid_identity", signal_identity)
    monkeypatch.setattr(
        module.os,
        "killpg",
        lambda pid, signal_number: group_signals.append((pid, signal_number)),
    )

    module._terminate_process_group(
        ReapedProcess(),
        0,
        "old-owned-start",
        {5000: "owned-child-start"},
    )

    assert group_signals == []
    assert individual_signals == [(5000, module.signal.SIGTERM)]


def test_pidfd_signal_rejects_reused_pid_identity(supervisor_module, monkeypatch):
    module = supervisor_module
    sent = []
    closed = []
    monkeypatch.setattr(module.os, "pidfd_open", lambda pid: 17)
    monkeypatch.setattr(module, "_process_start_time", lambda pid: "new-unrelated-start")
    monkeypatch.setattr(
        module.signal,
        "pidfd_send_signal",
        lambda pidfd, signal_number: sent.append((pidfd, signal_number)),
    )
    monkeypatch.setattr(module.os, "close", lambda pidfd: closed.append(pidfd))

    assert module._signal_pid_identity(4242, "old-owned-start", module.signal.SIGTERM) is False
    assert sent == []
    assert closed == [17]


def test_restart_cleans_a_checkpointed_detached_child(supervisor_module, tmp_path):
    module = supervisor_module
    child = module.subprocess.Popen(["sleep", "60"], start_new_session=True)
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    state["owned_process"] = {
        "pid": 999_999_999,
        "start_time": "1",
        "descendants": [{"pid": child.pid, "start_time": module._process_start_time(child.pid)}],
    }
    module.save_state(state_path, state)

    module.cleanup_stale_owned_process(state, state_path, grace=1)
    child.wait(timeout=2)

    assert module.load_state(state_path)["owned_process"] is None


def test_recovery_object_uses_stdin_not_process_arguments(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    fake_codex = tmp_path / "fake-codex"
    argv_file = tmp_path / "argv.json"
    stdin_file = tmp_path / "stdin.txt"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['TEST_ARGV']).write_text(json.dumps(sys.argv))\n"
        "Path(os.environ['TEST_STDIN']).write_text(sys.stdin.read())\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-one'}), flush=True)\n"
        "print(json.dumps({'type':'turn.started'}), flush=True)\n"
        "print(json.dumps({'type':'turn.completed'}), flush=True)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    monkeypatch.setenv("TEST_ARGV", str(argv_file))
    monkeypatch.setenv("TEST_STDIN", str(stdin_file))
    state = module.empty_state()
    secret_task_text = "ordinary canonical task body"
    state["in_flight"] = [
        {
            "attention_id": "attn-" + "9" * 32,
            "room_name": "backlog",
            "sender_agent_name": "peer",
            "sender_agent_id": "agent-peer",
            "sequence": 11,
            "body": secret_task_text,
            "requires_terminal": False,
        }
    ]
    state_path = tmp_path / "state.json"

    result = module.run_invocation(
        _config(module, tmp_path),
        state,
        state_path,
        {"room-1": "backlog"},
        [],
    )

    assert result.saw_turn_completed is True
    assert secret_task_text not in argv_file.read_text()
    assert secret_task_text in stdin_file.read_text()
