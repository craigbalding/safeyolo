"""Tests for the bounded guest-side Codex coord supervisor."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import time
import urllib.error
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SUPERVISOR_PATH = REPO_ROOT / "contrib/codex-coord-supervisor.py"
FAKE_CODEX_PATH = REPO_ROOT / "contrib/codex-coord-supervisor-fake-codex.sh"
WORK_ONE_TARGET = "https://example.test/work/one"
ISSUE_480_TARGET = "https://github.com/craigbalding/safeyolo/issues/480"
SECURITY_TARGET = "https://example.test/checks/security"
FORGE_WORK_TARGET = "https://example.test/work/forge"
LENS_WORK_TARGET = "https://example.test/work/lens"


def _review_target(pr: int = 10, head: str = "a" * 40) -> str:
    return f"https://github.com/craigbalding/safeyolo/pull/{pr}/commits/{head}"


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


def _factory_config(module: ModuleType, tmp_path: Path, role: str):
    agents = {"coordinator": "relay", "owner": "forge", "reviewer": "lens"}
    return _config(
        module,
        tmp_path,
        agent_name=agents[role],
        factory_name="backlog",
        factory_role=role,
        factory_roles=tuple(agents.items()),
        factory_handoffs=(
            module.Handoff(
                "TASK",
                "coordinator",
                "owner",
                ("DONE", "BLOCKED", "FAILED"),
                ("coordinator",),
            ),
            module.Handoff(
                "TASK",
                "coordinator",
                "reviewer",
                ("DONE", "BLOCKED", "FAILED"),
                ("coordinator",),
            ),
            module.Handoff(
                "REVIEW_READY",
                "owner",
                "reviewer",
                ("READY", "CHANGES_REQUIRED", "BLOCKED"),
                ("owner", "coordinator"),
            ),
        ),
        factory_operator_role="coordinator",
        factory_operator_types=("ACTIVATE", "PAUSE", "RESUME", "PRIORITY", "NEXT", "DIRECTION"),
        contract_sha256="a" * 64,
    )


def test_config_accepts_one_optional_agent_room(supervisor_module, tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "agent_name": "lens",
                "agent_room": "lens-agent",
                "rooms": ["backlog"],
                "coordinators": ["relay"],
            }
        )
    )

    config = supervisor_module.Config.load(path)

    assert config.agent_room == "lens-agent"


def test_config_rejects_invalid_agent_room(supervisor_module, tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "agent_name": "lens",
                "agent_room": "not a room",
                "rooms": ["backlog"],
                "coordinators": ["relay"],
            }
        )
    )

    with pytest.raises(supervisor_module.SupervisorError, match="agent_room"):
        supervisor_module.Config.load(path)


def _resolved(
    attention_id: str,
    *,
    sender: str = "relay",
    body: str = f"TASK target={WORK_ONE_TARGET} assignee=forge",
    room_id: str = "room-1",
    sender_kind: str = "agent",
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
            "sender_kind": sender_kind,
            "sender_agent_id": None if sender_kind == "operator" else f"agent-{sender}",
            "sender_agent_name": None if sender_kind == "operator" else sender,
            "content_type": "text/plain",
            "body": body,
            "sequence": 11,
        },
    }


def _resolved_brief(
    attention_id: str,
    *,
    revision: int = 1,
    markdown: str = "# Standing direction",
    room_id: str = "room-1",
):
    object_id = f"brief-{room_id}"
    return {
        "edge": {
            "attention_id": attention_id,
            "room_id": room_id,
            "kind": "brief_changed",
            "object_id": object_id,
            "revision_or_sequence": revision,
        },
        "object": {
            "room_id": room_id,
            "object_id": object_id,
            "revision": revision,
            "markdown": markdown,
            "content_hash": hashlib.sha256(markdown.encode()).hexdigest(),
            "updated_at": 1000 + revision,
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


def _terminal_event(
    attention_id: str,
    *,
    room_name: str = "backlog",
    body: str | None = None,
    sender: str = "forge",
    notify: str | list[str] | None = None,
):
    body = body or (
        f"DONE target={WORK_ONE_TARGET} attention_id={attention_id}\nresult=complete"
    )
    arguments = {"room_name": room_name, "body": body}
    if notify is not None:
        arguments["notify"] = notify
    if isinstance(notify, list):
        attention_intent = {"mode": "targeted"}
    elif notify == "room":
        attention_intent = {"mode": "room"}
    else:
        attention_intent = {"mode": "none"}
    return {
        "type": "item.completed",
        "item": {
            "type": "mcp_tool_call",
            "server": "safeyolo-coord",
            "tool": "send",
            "arguments": arguments,
            "result": {
                "structured_content": {
                    "envelope": {
                        "sender_kind": "agent",
                        "sender_agent_id": f"agent-{sender}",
                        "sender_agent_name": sender,
                        "body": body,
                    },
                    "sequence": 13,
                    "attention_status": "ready",
                    "attention_intent": attention_intent,
                }
            },
            "error": None,
            "status": "completed",
        },
    }


def _send_task_event(
    *,
    target: str = ISSUE_480_TARGET,
    assignee: str = "forge",
    detail: str = "Implement the issue.",
    room_name: str = "backlog",
    sender: str = "relay",
):
    body = f"TASK target={target} assignee={assignee}"
    if detail:
        body += f"\n\n{detail}"
    return {
        "type": "item.completed",
        "item": {
            "type": "mcp_tool_call",
            "server": "safeyolo-coord",
            "tool": "send_task",
            "arguments": {
                "room_name": room_name,
                "assignee": assignee,
                "target": target,
                "body": detail,
            },
            "result": {
                "structured_content": {
                    "envelope": {
                        "sender_kind": "agent",
                        "sender_agent_id": f"agent-{sender}",
                        "sender_agent_name": sender,
                        "body": body,
                    },
                    "sequence": 13,
                    "attention_status": "ready",
                    "attention_intent": {"mode": "targeted"},
                }
            },
            "error": None,
            "status": "completed",
        },
    }


def test_send_and_send_task_normalize_to_one_outbound_event(supervisor_module):
    module = supervisor_module
    body = f"TASK target={ISSUE_480_TARGET} assignee=forge\n\nImplement the issue."
    direct = _terminal_event(
        "attn-" + "0" * 32,
        body=body,
        sender="relay",
        notify=["forge"],
    )["item"]
    helper = _send_task_event()["item"]

    assert module._normalize_outbound_send(direct) == module._normalize_outbound_send(
        helper
    )


def test_send_task_rejects_legacy_nested_result(supervisor_module):
    item = _send_task_event()["item"]
    canonical_result = item["result"]["structured_content"]
    item["result"]["structured_content"] = {
        "send_result": canonical_result,
        "room_sequence": canonical_result["sequence"],
    }

    assert supervisor_module._normalize_outbound_send(item) is None


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

    persisted = module.load_state(state_path)
    assert persisted["in_flight"] == []
    assert persisted["recent_attention_ids"] == [attention_id]


@pytest.mark.parametrize(
    "body",
    [
        f"TASK target={WORK_ONE_TARGET} assignee=lens",
        f"TASK target={WORK_ONE_TARGET}",
        f"TASK target={WORK_ONE_TARGET} assignee=forge assignee=forge",
    ],
)
def test_task_for_another_or_ambiguous_assignee_is_not_promoted(supervisor_module, tmp_path, body):
    module = supervisor_module
    attention_id = "attn-" + "8" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [_resolved(attention_id, body=body)]))

    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


@pytest.mark.parametrize(
    "body",
    [
        "TASK UPDATE assignee=forge",
        f"TASK target={WORK_ONE_TARGET} assignee=forge extra=true",
        f"TASK assignee=forge target={WORK_ONE_TARGET}",
        f"TASK target={WORK_ONE_TARGET} assignee=forge assignee=forge",
        "TASK target=not-a-url assignee=forge",
        "TASK task=one assignee=forge",
    ],
)
def test_generic_task_header_requires_exact_canonical_form(supervisor_module, tmp_path, body):
    module = supervisor_module
    attention_id = "attn-" + "0" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(_config(module, tmp_path), state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [_resolved(attention_id, body=body)]))

    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


def test_target_query_values_survive_assignment_and_terminal_correlation(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    attention_id = "attn-" + "7" * 32
    target = "https://example.test/work/one?kind=issue&id=480"
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _config(module, tmp_path),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, body=f"TASK target={target} assignee=forge")],
        )
    )
    assert state["in_flight"][0]["attention_id"] == attention_id

    consumer.consume(
        _terminal_event(
            attention_id,
            body=(
                "DONE target=https://example.test/work/one?kind=issue&id=481 "
                f"attention_id={attention_id}"
            ),
        )
    )
    assert state["in_flight"][0]["attention_id"] == attention_id

    consumer.consume(
        _terminal_event(
            attention_id,
            body=f"DONE target={target} attention_id={attention_id}",
        )
    )
    assert state["in_flight"] == []


def test_factory_review_response_must_notify_every_declared_recipient(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    attention_id = "attn-" + "1" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    config = _factory_config(module, tmp_path, "reviewer")
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})
    target = _review_target()
    body = f"REVIEW_READY target={target}"

    consumer.consume(_wait_event(module, state, [_resolved(attention_id, sender="forge", body=body)]))

    assert state["in_flight"][0]["requires_terminal"] is True
    response = f"READY target={target} attention_id={attention_id}"
    consumer.consume(
        _terminal_event(
            attention_id,
            body=response,
            sender="lens",
            notify=["forge"],
        )
    )
    assert module.load_state(state_path)["in_flight"][0]["attention_id"] == attention_id

    consumer.consume(
        _terminal_event(
            attention_id,
            body=response,
            sender="lens",
            notify=["forge", "relay"],
        )
    )
    assert module.load_state(state_path)["in_flight"] == []


def test_factory_admits_coordinator_non_code_task_to_reviewer(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "9" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    config = _factory_config(module, tmp_path, "reviewer")
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})
    body = f"TASK target={SECURITY_TARGET} assignee=lens"

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, sender="relay", body=body)],
        )
    )

    assert state["in_flight"][0]["requires_terminal"] is True
    response = f"DONE target={SECURITY_TARGET} attention_id={attention_id}"
    consumer.consume(
        _terminal_event(
            attention_id,
            body=response,
            sender="lens",
            notify=["relay"],
        )
    )
    assert module.load_state(state_path)["in_flight"] == []


@pytest.mark.parametrize("response_type", ["READY", "CHANGES_REQUIRED", "BLOCKED"])
def test_factory_admits_every_reviewer_to_owner_response(supervisor_module, tmp_path, response_type):
    module = supervisor_module
    task_attention = "attn-" + "2" * 32
    review_attention = "attn-" + "3" * 32
    response_attention = "attn-" + "4" * 32
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": task_attention,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 10,
            "body": f"TASK target={ISSUE_480_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    state["awaiting_handoffs"] = [
        {
            "room_name": "backlog",
            "request": "REVIEW_READY",
            "recipient_agent": "lens",
            "body": f"REVIEW_READY target={_review_target()}",
            "correlation": {"target": _review_target()},
        }
    ]
    state_path = tmp_path / "state.json"
    config = _factory_config(module, tmp_path, "owner")
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})
    response = f"{response_type} target={_review_target()} attention_id={review_attention}"

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(response_attention, sender="lens", body=response)],
        )
    )

    assert state["awaiting_handoffs"] == []
    assert state["in_flight"][-1]["attention_id"] == response_attention
    assert state["in_flight"][-1]["requires_terminal"] is False


@pytest.mark.parametrize(
    "response",
    [
        f"READY target={_review_target(pr=11)}",
        f"READY target={_review_target(head='b' * 40)}",
        "READY target=not-a-url",
        f"READY target={_review_target()} extra=true",
    ],
)
def test_factory_rejects_a_response_for_a_different_review_object(
    supervisor_module,
    tmp_path,
    response,
):
    module = supervisor_module
    task_attention = "attn-" + "2" * 32
    response_attention = "attn-" + "4" * 32
    request_attention = "attn-" + "3" * 32
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": task_attention,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 10,
            "body": f"TASK target={ISSUE_480_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    awaiting = {
        "room_name": "backlog",
        "request": "REVIEW_READY",
        "recipient_agent": "lens",
        "body": f"REVIEW_READY target={_review_target()}",
        "correlation": {"target": _review_target()},
    }
    state["awaiting_handoffs"] = [awaiting]
    state_path = tmp_path / "state.json"
    config = _factory_config(module, tmp_path, "owner")
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})

    consumer.consume(
        _wait_event(
            module,
            state,
            [
                _resolved(
                    response_attention,
                    sender="lens",
                    body=f"{response} attention_id={request_attention}",
                )
            ],
        )
    )

    assert state["awaiting_handoffs"] == [awaiting]
    assert [item["attention_id"] for item in state["in_flight"]] == [task_attention]
    assert state["recent_attention_ids"] == [response_attention]


@pytest.mark.parametrize(
    ("sender", "body", "sender_kind"),
    [
        ("peer", f"REVIEW_READY target={_review_target()}", "agent"),
        ("forge", "REVIEW_READY_UPDATE issue=#480", "agent"),
        ("forge", f"REVIEW_READY target={_review_target()}", "user"),
        ("relay", "TASK UPDATE assignee=lens", "agent"),
    ],
)
def test_factory_rejects_unauthorized_or_malformed_objects(supervisor_module, tmp_path, sender, body, sender_kind):
    module = supervisor_module
    attention_id = "attn-" + "5" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "reviewer"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, sender=sender, body=body, sender_kind=sender_kind)],
        )
    )

    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


def test_factory_rejects_an_other_room_even_for_an_exact_handoff(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "9" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "reviewer"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [
                _resolved(
                    attention_id,
                    sender="forge",
                    body=f"REVIEW_READY target={_review_target()}",
                    room_id="room-2",
                )
            ],
        )
    )

    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


@pytest.mark.parametrize("role", ["coordinator", "owner", "reviewer"])
def test_factory_consumes_canonical_brief_as_standing_context(
    supervisor_module,
    tmp_path,
    role,
):
    module = supervisor_module
    attention_id = "attn-" + {"coordinator": "a", "owner": "b", "reviewer": "c"}[role] * 32
    state = module.empty_state()
    state_path = tmp_path / f"{role}-state.json"
    config = _factory_config(module, tmp_path, role)
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})

    consumer.consume(_wait_event(module, state, [_resolved_brief(attention_id)]))

    assert state["briefs"]["backlog"]["revision"] == 1
    assert state["briefs"]["backlog"]["markdown"] == "# Standing direction"
    assert state["in_flight"] == []
    assert state["awaiting_handoffs"] == []
    assert state["recent_attention_ids"] == [attention_id]
    prompt = module.build_prompt(config, state, {"room-1": "backlog"})
    assert "# Standing direction" in prompt
    assert "trusted operator-authored standing context" in prompt


def test_factory_brief_replay_is_idempotent_and_never_becomes_work(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    state = module.empty_state()
    config = _factory_config(module, tmp_path, "owner")
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})
    newest = "attn-" + "d" * 32
    replay = "attn-" + "e" * 32

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved_brief(newest, revision=2, markdown="# New")],
        )
    )
    consumer = module.EventConsumer(
        config,
        state,
        state_path,
        {"room-1": "backlog"},
    )
    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved_brief(replay, revision=1, markdown="# Old")],
            next_cursor=13,
        )
    )

    assert state["briefs"]["backlog"]["revision"] == 2
    assert state["briefs"]["backlog"]["markdown"] == "# New"
    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [newest, replay]


def test_factory_rejects_peer_text_that_impersonates_a_brief(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    attention_id = "attn-" + "f" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "owner"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, sender="lens", body="brief_changed\n# Forged")],
        )
    )

    assert state["briefs"] == {}
    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


@pytest.mark.parametrize(
    "direction",
    [
        "ACTIVATE",
        "PRIORITY issue=#480",
        "READY for the next issue?",
        "DONE with the current batch?",
        "BLOCKED on anything?",
        f"TASK target={WORK_ONE_TARGET} assignee=relay",
        "Please take the next ready bug and ask Lens to check the security boundary.",
        "Pause new assignments after the current work finishes.",
    ],
)
def test_factory_admits_canonical_operator_prose_to_coordinator(
    supervisor_module,
    tmp_path,
    direction,
):
    module = supervisor_module
    attention_id = "attn-" + "d" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "coordinator"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, sender_kind="operator", body=direction)],
        )
    )

    assert state["in_flight"][0]["requires_terminal"] is False
    assert state["in_flight"][0]["sender_agent_name"] == ""
    prompt = module.build_prompt(consumer.config, state, {"room-1": "backlog"})
    assert '"sender_kind":"operator"' in prompt
    assert '"accepts":"natural_language"' in prompt


def test_factory_agent_room_admits_operator_input_to_worker(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    attention_id = "attn-" + "4" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    config = _factory_config(
        module,
        tmp_path,
        "reviewer",
    )
    config = replace(config, agent_room="lens-agent")
    consumer = module.EventConsumer(
        config,
        state,
        state_path,
        {"room-1": "backlog", "room-2": "lens-agent"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [
                _resolved(
                    attention_id,
                    sender_kind="operator",
                    body="Report your current wait cursor.",
                    room_id="room-2",
                )
            ],
        )
    )

    assert state["in_flight"][0]["room_name"] == "lens-agent"
    assert state["in_flight"][0]["requires_terminal"] is False
    prompt = module.build_prompt(config, state, consumer.room_ids)
    assert "direct operator direction" in prompt


def test_factory_status_question_creates_no_persisted_workflow_object(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    attention_id = "attn-" + "7" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "coordinator"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [
                _resolved(
                    attention_id,
                    sender_kind="operator",
                    body="What is the current factory status?",
                )
            ],
        )
    )
    consumer.consume(
        _terminal_event(
            attention_id,
            body="The current assigned work remains in progress.",
            sender="relay",
        )
    )
    consumer.consume({"type": "turn.completed"})

    persisted = module.load_state(state_path)
    assert persisted["in_flight"] == []
    assert persisted["awaiting_handoffs"] == []
    assert persisted["recent_attention_ids"] == [attention_id]


@pytest.mark.parametrize(
    ("role", "sender_kind", "body"),
    [
        ("coordinator", "agent", "ACTIVATE"),
        ("owner", "operator", "ACTIVATE"),
        ("coordinator", "operator", "   "),
        ("coordinator", "operator", "DIRECTION\n" + "x" * 4096),
    ],
)
def test_factory_rejects_operator_lockout_and_peer_impersonation_cases(
    supervisor_module,
    tmp_path,
    role,
    sender_kind,
    body,
):
    module = supervisor_module
    attention_id = "attn-" + "e" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, role),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    consumer.consume(
        _wait_event(
            module,
            state,
            [_resolved(attention_id, sender="relay", sender_kind=sender_kind, body=body)],
        )
    )

    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


def test_factory_canonical_operator_to_terminal_chain(supervisor_module, tmp_path):
    module = supervisor_module
    room_ids = {"room-1": "backlog"}
    relay_state = module.empty_state()
    forge_state = module.empty_state()
    lens_state = module.empty_state()
    relay = module.EventConsumer(
        _factory_config(module, tmp_path, "coordinator"),
        relay_state,
        tmp_path / "relay-state.json",
        room_ids,
    )
    forge = module.EventConsumer(
        _factory_config(module, tmp_path, "owner"),
        forge_state,
        tmp_path / "forge-state.json",
        room_ids,
    )
    lens = module.EventConsumer(
        _factory_config(module, tmp_path, "reviewer"),
        lens_state,
        tmp_path / "lens-state.json",
        room_ids,
    )
    control_attention = "attn-" + "1" * 32
    task_attention = "attn-" + "2" * 32
    review_attention = "attn-" + "3" * 32
    forge_ready_attention = "attn-" + "4" * 32
    relay_ready_attention = "attn-" + "5" * 32
    done_attention = "attn-" + "6" * 32

    relay.consume(
        _wait_event(
            module,
            relay_state,
            [_resolved(control_attention, sender_kind="operator", body="ACTIVATE")],
        )
    )
    assert relay_state["in_flight"][0]["requires_terminal"] is False
    relay.consume({"type": "turn.completed"})

    task_body = f"TASK target={ISSUE_480_TARGET} assignee=forge\n\nImplement the issue."
    task_send = _send_task_event()
    relay.consume(task_send)
    assert relay_state["awaiting_handoffs"][0]["request"] == "TASK"
    forge.consume(
        _wait_event(
            module,
            forge_state,
            [_resolved(task_attention, sender="relay", body=task_body)],
        )
    )
    assert forge_state["in_flight"][0]["requires_terminal"] is True

    review_target = _review_target(pr=485)
    review_body = f"REVIEW_READY target={review_target}"
    review_send = _terminal_event(
        task_attention,
        body=review_body,
        sender="forge",
        notify=["lens"],
    )
    forge.consume(review_send)
    lens.consume(
        _wait_event(
            module,
            lens_state,
            [_resolved(review_attention, sender="forge", body=review_body)],
        )
    )
    assert lens_state["in_flight"][0]["requires_terminal"] is True

    ready_body = f"READY target={review_target} attention_id={review_attention}"
    lens.consume(
        _terminal_event(
            review_attention,
            body=ready_body,
            sender="lens",
            notify=["forge", "relay"],
        )
    )
    assert lens_state["in_flight"] == []
    forge = module.EventConsumer(
        _factory_config(module, tmp_path, "owner"),
        forge_state,
        tmp_path / "forge-state.json",
        room_ids,
    )
    forge.consume(
        _wait_event(
            module,
            forge_state,
            [_resolved(forge_ready_attention, sender="lens", body=ready_body)],
        )
    )
    assert forge_state["awaiting_handoffs"] == []

    relay = module.EventConsumer(
        _factory_config(module, tmp_path, "coordinator"),
        relay_state,
        tmp_path / "relay-state.json",
        room_ids,
    )
    relay.consume(
        _wait_event(
            module,
            relay_state,
            [_resolved(relay_ready_attention, sender="lens", body=ready_body)],
            next_cursor=13,
        )
    )
    assert relay_state["awaiting_handoffs"][0]["recipient_agent"] == "forge"
    assert relay_state["in_flight"][-1]["attention_id"] == relay_ready_attention
    assert relay_state["in_flight"][-1]["requires_terminal"] is False
    relay.consume({"type": "turn.completed"})

    done_body = f"DONE target={ISSUE_480_TARGET} attention_id={task_attention}"
    forge.consume(
        _terminal_event(
            task_attention,
            body=done_body,
            sender="forge",
            notify=["relay"],
        )
    )
    assert forge_state["in_flight"][-1]["requires_terminal"] is False
    relay = module.EventConsumer(
        _factory_config(module, tmp_path, "coordinator"),
        relay_state,
        tmp_path / "relay-state.json",
        room_ids,
    )
    relay.consume(
        _wait_event(
            module,
            relay_state,
            [_resolved(done_attention, sender="forge", body=done_body)],
            next_cursor=14,
        )
    )
    assert relay_state["awaiting_handoffs"] == []
    assert relay_state["in_flight"][-1]["requires_terminal"] is False


def test_factory_send_task_requires_matching_targeted_envelope(supervisor_module, tmp_path):
    module = supervisor_module
    state = module.empty_state()
    state_path = tmp_path / "relay-state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "coordinator"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    event = _send_task_event()
    event["item"]["result"]["structured_content"]["attention_status"] = "none"
    consumer.consume(event)
    assert state["awaiting_handoffs"] == []

    consumer.consume(_send_task_event())
    assert state["awaiting_handoffs"] == [
        {
            "room_name": "backlog",
            "request": "TASK",
            "recipient_agent": "forge",
            "body": f"TASK target={ISSUE_480_TARGET} assignee=forge\n\nImplement the issue.",
            "correlation": {"target": ISSUE_480_TARGET},
        }
    ]
    assert consumer.result.handoff_observed is True


def test_factory_rejects_a_terminal_outside_the_declared_response_set(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "a" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    config = _factory_config(module, tmp_path, "reviewer")
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})
    target = _review_target()
    body = f"REVIEW_READY target={target}"
    consumer.consume(_wait_event(module, state, [_resolved(attention_id, sender="forge", body=body)]))

    consumer.consume(
        _terminal_event(
            attention_id,
            body=f"DONE target={target} attention_id={attention_id}",
            sender="lens",
            notify=["forge", "relay"],
        )
    )

    assert module.load_state(state_path)["in_flight"][0]["attention_id"] == attention_id
    assert consumer.result.terminal_observed is False


def test_factory_response_requires_a_correlated_outbound_handoff(supervisor_module, tmp_path):
    module = supervisor_module
    attention_id = "attn-" + "6" * 32
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "owner"),
        state,
        state_path,
        {"room-1": "backlog"},
    )
    body = f"READY target={_review_target()} attention_id={'attn-' + '7' * 32}"

    consumer.consume(_wait_event(module, state, [_resolved(attention_id, sender="lens", body=body)]))

    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


def test_factory_outbound_request_suspends_parent_for_next_bounded_wait(supervisor_module, tmp_path):
    module = supervisor_module
    task_attention = "attn-" + "8" * 32
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": task_attention,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 10,
            "body": f"TASK target={ISSUE_480_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    state_path = tmp_path / "state.json"
    config = _factory_config(module, tmp_path, "owner")
    consumer = module.EventConsumer(config, state, state_path, {"room-1": "backlog"})
    body = f"REVIEW_READY target={_review_target()}"
    event = _terminal_event(task_attention, body=body, notify=["lens"])

    consumer.consume(event)

    assert state["in_flight"][0]["attention_id"] == task_attention
    expected = {
        "room_name": "backlog",
        "request": "REVIEW_READY",
        "recipient_agent": "lens",
        "body": body,
        "correlation": {"target": _review_target()},
    }
    assert state["awaiting_handoffs"] == [expected]
    assert module.load_state(state_path)["awaiting_handoffs"] == [expected]
    assert consumer.result.handoff_observed is True
    prompt = module.build_prompt(config, state, {"room-1": "backlog"})
    assert "Do not call wait_for_coord in this turn" in prompt
    assert "unmatched outbound handoff is suspended" in prompt


def test_factory_prompt_directs_required_outbound_handoff_before_terminal(supervisor_module, tmp_path):
    module = supervisor_module
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": "attn-" + "8" * 32,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 10,
            "body": f"TASK target={ISSUE_480_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]

    prompt = module.build_prompt(
        _factory_config(module, tmp_path, "owner"),
        state,
        {"room-1": "backlog"},
    )

    assert "requires a declared outbound handoff, send the targeted handoff" in prompt
    assert "Do not finish merely because one handoff is now waiting" in prompt
    assert "advance every other ready in-flight object before finishing" in prompt
    assert "Do not send an inbound response merely because the required downstream response has not arrived" in prompt
    assert "only when the request has a genuine terminal outcome" in prompt
    assert "Repeat the request's exact target" in prompt
    assert "in the leading response header" in prompt


def test_factory_tracks_concurrent_forge_and_lens_tasks_across_restart(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    room_ids = {"room-1": "backlog"}
    state_path = tmp_path / "relay-state.json"
    state = module.empty_state()
    config = _factory_config(module, tmp_path, "coordinator")
    consumer = module.EventConsumer(config, state, state_path, room_ids)

    forge_body = f"TASK target={FORGE_WORK_TARGET} assignee=forge"
    forge_send = _terminal_event(
        "attn-" + "1" * 32,
        body=forge_body,
        sender="relay",
        notify=["forge"],
    )
    lens_body = f"TASK target={LENS_WORK_TARGET} assignee=lens"
    lens_send = _terminal_event(
        "attn-" + "2" * 32,
        body=lens_body,
        sender="relay",
        notify=["lens"],
    )

    consumer.consume(forge_send)
    consumer.consume(lens_send)

    assert [item["recipient_agent"] for item in state["awaiting_handoffs"]] == [
        "forge",
        "lens",
    ]
    state = module.load_state(state_path)
    consumer = module.EventConsumer(config, state, state_path, room_ids)

    wrong_sender = "attn-" + "3" * 32
    wrong_room = "attn-" + "4" * 32
    lens_response_attention = "attn-" + "5" * 32
    lens_request_attention = "attn-" + "6" * 32
    lens_done = f"DONE target={LENS_WORK_TARGET} attention_id={lens_request_attention}"
    consumer.consume(
        _wait_event(
            module,
            state,
            [
                _resolved(
                    wrong_sender,
                    sender="lens",
                    body=f"DONE target={FORGE_WORK_TARGET} attention_id={lens_request_attention}",
                ),
                _resolved(
                    wrong_room,
                    sender="lens",
                    body=lens_done,
                    room_id="room-other",
                ),
                _resolved(lens_response_attention, sender="lens", body=lens_done),
            ],
        )
    )

    assert [item["recipient_agent"] for item in state["awaiting_handoffs"]] == ["forge"]
    consumer.consume({"type": "turn.completed"})
    state = module.load_state(state_path)
    assert lens_response_attention in state["recent_attention_ids"]

    consumer = module.EventConsumer(config, state, state_path, room_ids)
    forge_response_attention = "attn-" + "7" * 32
    forge_request_attention = "attn-" + "8" * 32
    forge_done = f"DONE target={FORGE_WORK_TARGET} attention_id={forge_request_attention}"
    consumer.consume(
        _wait_event(
            module,
            state,
            [
                _resolved(lens_response_attention, sender="lens", body=lens_done),
                _resolved(forge_response_attention, sender="forge", body=forge_done),
            ],
            next_cursor=13,
        )
    )

    assert state["awaiting_handoffs"] == []
    assert [item["attention_id"] for item in state["in_flight"]] == [forge_response_attention]


def test_factory_rejects_persisted_handoff_correlation_that_does_not_match_request(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    state = module.empty_state()
    state["awaiting_handoffs"] = [
        {
            "room_name": "backlog",
            "request": "REVIEW_READY",
            "recipient_agent": "lens",
            "body": f"REVIEW_READY target={_review_target(pr=485)}",
            "correlation": {"target": _review_target(pr=486)},
        }
    ]
    state_path = _write_json(tmp_path / "state.json", state)

    with pytest.raises(module.SupervisorError, match="mismatched awaiting-handoff correlation"):
        module.load_state(state_path)


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
    assert "Do not call wait_for_coord" in prompt
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
            "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
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
                    "body": f"DONE target={WORK_ONE_TARGET} attention_id={attention_id}",
                }
            ],
            "next_cursor": 12,
            "has_more": False,
        },
    )

    assert module.reconcile_terminals(_config(module, tmp_path), state) is True
    assert state["in_flight"] == []
    assert state["recent_attention_ids"] == [attention_id]


def test_terminal_requires_exact_target_and_attention_id(supervisor_module):
    module = supervisor_module
    pending = {
        "attention_id": "attn-" + "1" * 32,
        "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
    }

    assert module._terminal_matches(pending, f"DONE target={WORK_ONE_TARGET}") is False
    assert module._terminal_matches(pending, "DONE target=https://example.test/work/two") is False
    assert (
        module._terminal_matches(
            pending,
            f"DONE target={WORK_ONE_TARGET} attention_id={'attn-' + '2' * 32}",
        )
        is False
    )
    assert (
        module._terminal_matches(
            pending,
            f"DONE target={WORK_ONE_TARGET} attention_id={'attn-' + '1' * 32}",
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

    consumer.consume(
        _terminal_event(first, body=f"DONE target={WORK_ONE_TARGET}\nresult=complete")
    )

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
            "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
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
            "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    module.save_state(state_path, state)
    monkeypatch.setattr(
        module,
        "preflight",
        lambda config, state=None: {"room-1": "backlog"},
    )
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


def test_recovered_work_preserves_thread_after_successful_handoff(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    state_path = tmp_path / "state.json"
    state = module.empty_state()
    state["thread_id"] = "healthy-recovered-thread"
    state["in_flight"] = [
        {
            "attention_id": "attn-" + "f" * 32,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": f"TASK target={ISSUE_480_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    module.save_state(state_path, state)
    monkeypatch.setattr(module, "preflight", lambda config, state=None: {"room-1": "backlog"})
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)

    def invoke(config, state, current_path, room_ids, codex_args):
        state["awaiting_handoffs"] = [
            {
                "room_name": "backlog",
                "request": "REVIEW_READY",
                "recipient_agent": "lens",
                "body": f"REVIEW_READY target={_review_target()}",
                "correlation": {"target": _review_target()},
            }
        ]
        return module.InvocationResult(
            saw_turn_started=True,
            saw_turn_completed=True,
            handoff_observed=True,
        )

    monkeypatch.setattr(module, "run_invocation", invoke)
    supervisor = module.Supervisor(_factory_config(module, tmp_path, "owner"), state_path, [])

    assert supervisor.cycle() is True
    persisted = module.load_state(state_path)
    assert persisted["thread_id"] == "healthy-recovered-thread"
    assert persisted["awaiting_handoffs"][0]["recipient_agent"] == "lens"


def test_empty_external_wait_does_not_launch_codex(
    supervisor_module,
    tmp_path,
    monkeypatch,
    capsys,
):
    module = supervisor_module
    state_path = tmp_path / "state.json"
    module.save_state(state_path, module.empty_state())
    monkeypatch.setattr(
        module,
        "preflight",
        lambda config, state=None: {"room-1": "backlog"},
    )
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)
    waits = []
    monkeypatch.setattr(
        module,
        "wait_for_attention_page",
        lambda config, state: waits.append(state["safe_cursor"])
        or {"objects": [], "next_cursor": state["safe_cursor"]},
    )
    monkeypatch.setattr(
        module,
        "run_invocation",
        lambda *args: pytest.fail("empty attention must not launch Codex"),
    )
    supervisor = module.Supervisor(_config(module, tmp_path), state_path, [], debug=True)

    assert supervisor.cycle() is True
    assert waits == [0]
    assert module.load_state(state_path)["consecutive_failures"] == 0
    debug_events = [
        json.loads(line.removeprefix("codex-coord-supervisor: debug "))["event"]
        for line in capsys.readouterr().err.splitlines()
    ]
    assert debug_events == ["wait.begin", "wait.page", "wait.accepted", "cycle.rearm"]


def test_external_wait_resolves_the_whole_page_before_returning_cursor(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    first = "attn-" + "1" * 32
    second = "attn-" + "2" * 32
    state = module.empty_state()
    state["safe_cursor"] = 7
    calls = []

    def api(path, **kwargs):
        calls.append((path, kwargs.get("timeout_seconds")))
        if path.startswith("/api/coord/attention/wait?"):
            return {
                "edges": [{"attention_id": first}, {"attention_id": second}],
                "next_cursor": 9,
            }
        attention_id = path.split("/")[-2]
        return _resolved(attention_id)

    monkeypatch.setattr(module, "_api_json", api)

    page = module.wait_for_attention_page(_config(module, tmp_path), state)

    assert [item["edge"]["attention_id"] for item in page["objects"]] == [first, second]
    assert page["next_cursor"] == 9
    assert "since=7" in calls[0][0]
    assert "timeout=5" in calls[0][0]
    assert "limit=16" in calls[0][0]
    assert calls[0][1] == 35.0
    assert [call[0] for call in calls[1:]] == [
        f"/api/coord/attention/{first}/object",
        f"/api/coord/attention/{second}/object",
    ]


def test_external_wait_partial_resolution_never_exposes_cursor(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    first = "attn-" + "3" * 32
    second = "attn-" + "4" * 32
    state = module.empty_state()
    state["safe_cursor"] = 7

    def api(path, **kwargs):
        if path.startswith("/api/coord/attention/wait?"):
            return {
                "edges": [{"attention_id": first}, {"attention_id": second}],
                "next_cursor": 9,
            }
        if second in path:
            raise module.SupervisorError("canonical object unavailable")
        return _resolved(first)

    monkeypatch.setattr(module, "_api_json", api)

    with pytest.raises(module.SupervisorError, match="canonical object unavailable"):
        module.wait_for_attention_page(_config(module, tmp_path), state)

    assert state["safe_cursor"] == 7


def test_resolved_page_validation_is_atomic(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    state = module.empty_state()
    state["safe_cursor"] = 7
    original = json.loads(json.dumps(state))
    state_path = tmp_path / "state.json"
    module.save_state(state_path, state)
    consumer = module.EventConsumer(
        _factory_config(module, tmp_path, "owner"),
        state,
        state_path,
        {"room-1": "backlog"},
    )

    with pytest.raises(module.SupervisorError, match="invalid .* object"):
        consumer.accept_attention_page(
            [_resolved_brief("attn-" + "a" * 32), {"invalid": True}],
            9,
        )

    assert state == original
    assert module.load_state(state_path) == original


def test_actionable_external_attention_launches_one_codex_turn(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    attention_id = "attn-" + "5" * 32
    state_path = tmp_path / "state.json"
    module.save_state(state_path, module.empty_state())
    monkeypatch.setattr(module, "preflight", lambda config, state=None: {"room-1": "backlog"})
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)
    monkeypatch.setattr(
        module,
        "wait_for_attention_page",
        lambda config, state: {"objects": [_resolved(attention_id)], "next_cursor": 1},
    )
    invocations = []

    def invoke(config, state, current_path, room_ids, codex_args):
        invocations.append([item["attention_id"] for item in state["in_flight"]])
        consumer = module.EventConsumer(config, state, current_path, room_ids)
        consumer.consume({"type": "turn.started"})
        consumer.consume(_terminal_event(attention_id))
        consumer.consume({"type": "turn.completed"})
        return consumer.result

    monkeypatch.setattr(module, "run_invocation", invoke)
    supervisor = module.Supervisor(_config(module, tmp_path), state_path, [])

    assert supervisor.cycle() is True
    assert invocations == [[attention_id]]
    persisted = module.load_state(state_path)
    assert persisted["safe_cursor"] == 1
    assert persisted["in_flight"] == []
    assert persisted["recent_attention_ids"] == [attention_id]


def test_new_external_work_preserves_thread_after_outbound_handoff(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    attention_id = "attn-" + "5" * 32
    state_path = tmp_path / "state.json"
    state = module.empty_state()
    state["thread_id"] = "healthy-thread"
    module.save_state(state_path, state)
    config = _factory_config(module, tmp_path, "owner")
    monkeypatch.setattr(module, "preflight", lambda config, state=None: {"room-1": "backlog"})
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)
    monkeypatch.setattr(
        module,
        "wait_for_attention_page",
        lambda config, state: {
            "objects": [
                _resolved(
                    attention_id,
                    sender="relay",
                    body=f"TASK target={ISSUE_480_TARGET} assignee=forge",
                )
            ],
            "next_cursor": 1,
        },
    )

    def invoke(config, state, current_path, room_ids, codex_args):
        state["awaiting_handoffs"] = [
            {
                "room_name": "backlog",
                "request": "REVIEW_READY",
                "recipient_agent": "lens",
                "body": f"REVIEW_READY target={_review_target()}",
                "correlation": {"target": _review_target()},
            }
        ]
        return module.InvocationResult(
            saw_turn_started=True,
            saw_turn_completed=True,
            handoff_observed=True,
        )

    monkeypatch.setattr(module, "run_invocation", invoke)
    supervisor = module.Supervisor(config, state_path, [])

    assert supervisor.cycle() is True
    persisted = module.load_state(state_path)
    assert persisted["thread_id"] == "healthy-thread"
    assert persisted["in_flight"][0]["attention_id"] == attention_id
    assert persisted["awaiting_handoffs"][0]["recipient_agent"] == "lens"


def test_brief_only_external_attention_does_not_launch_codex(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    attention_id = "attn-" + "6" * 32
    state_path = tmp_path / "state.json"
    module.save_state(state_path, module.empty_state())
    monkeypatch.setattr(module, "preflight", lambda config, state=None: {"room-1": "backlog"})
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, current: False)
    monkeypatch.setattr(
        module,
        "wait_for_attention_page",
        lambda config, state: {"objects": [_resolved_brief(attention_id)], "next_cursor": 1},
    )
    monkeypatch.setattr(
        module,
        "run_invocation",
        lambda *args: pytest.fail("a brief revision must not launch Codex"),
    )
    supervisor = module.Supervisor(_factory_config(module, tmp_path, "owner"), state_path, [])

    assert supervisor.cycle() is True
    persisted = module.load_state(state_path)
    assert persisted["safe_cursor"] == 1
    assert persisted["briefs"]["backlog"]["revision"] == 1
    assert persisted["recent_attention_ids"] == [attention_id]


def test_fake_codex_harness_captures_prompt_and_emits_valid_events(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    capture = tmp_path / "capture"
    environment = module.os.environ.copy()
    environment["SAFEYOLO_FAKE_CODEX_CAPTURE_DIR"] = str(capture)

    login = module.subprocess.run(
        [str(FAKE_CODEX_PATH), "login", "status"],
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    invocation = module.subprocess.run(
        [str(FAKE_CODEX_PATH), "exec", "--json", "-"],
        input="supervisor checkpoint\n",
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )

    assert login.returncode == 0
    assert "Logged in using ChatGPT" in login.stdout
    assert invocation.returncode == 0
    assert [json.loads(line)["type"] for line in invocation.stdout.splitlines()] == [
        "thread.started",
        "turn.started",
        "turn.completed",
    ]
    assert next(capture.glob("*.argv")).read_text().splitlines() == ["exec", "--json", "-"]
    assert next(capture.glob("*.stdin")).read_text() == "supervisor checkpoint\n"


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


def test_agent_api_error_preserves_bounded_nats_failure_classification(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    token = tmp_path / "agent-token"
    token.write_text("not-a-real-token")
    monkeypatch.setenv("SAFEYOLO_COORD_TOKEN_PATH", str(token))
    error = urllib.error.HTTPError(
        "http://_safeyolo.proxy.internal/api/coord/attention/wait",
        503,
        "Service Unavailable",
        {"Retry-After": "4"},
        BytesIO(b'{"error":"coordination substrate unavailable"}'),
    )

    def unavailable(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(module.urllib.request, "urlopen", unavailable)

    with pytest.raises(module.AgentApiRequestError) as caught:
        module._api_json("/api/coord/attention/wait")

    assert caught.value.status == 503
    assert caught.value.retry_after == "4"
    assert caught.value.path == "/api/coord/attention/wait"
    assert "coordination substrate unavailable" in str(caught.value)
    assert "not-a-real-token" not in str(caught.value)


def test_successful_initial_preflight_avoids_rechecking_login_each_cycle(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    state_path = tmp_path / "state.json"
    module.save_state(state_path, module.empty_state())
    calls = []
    monkeypatch.setattr(
        module,
        "preflight",
        lambda config, state=None: calls.append("initial") or {"room-1": "backlog"},
    )
    monkeypatch.setattr(
        module,
        "_coord_preflight",
        lambda config, state=None: calls.append("coord") or {"room-1": "backlog"},
    )
    monkeypatch.setattr(module, "reconcile_terminals", lambda config, state: False)
    monkeypatch.setattr(
        module,
        "wait_for_attention_page",
        lambda config, state: {"objects": [], "next_cursor": state["safe_cursor"]},
    )
    supervisor = module.Supervisor(_config(module, tmp_path), state_path, [])

    assert supervisor.cycle() is True
    assert supervisor.cycle() is True
    assert calls == ["initial", "coord"]


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


def test_checkpoint_rejects_old_in_flight_task_protocol(supervisor_module, tmp_path):
    module = supervisor_module
    state = module.empty_state()
    state["in_flight"] = [
        {
            "attention_id": "attn-" + "5" * 32,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": "TASK task=one assignee=forge",
            "requires_terminal": True,
        }
    ]

    with pytest.raises(module.SupervisorError, match="unsupported request protocol"):
        module.load_state(_write_json(tmp_path / "old-protocol-state.json", state))


def test_version_three_checkpoint_migrates_with_empty_brief_context(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    state = module.empty_state()
    state["version"] = 3
    state["awaiting_handoff"] = None
    state.pop("awaiting_handoffs")
    state.pop("briefs")

    migrated = module.load_state(_write_json(tmp_path / "v3-state.json", state))

    assert migrated["version"] == module.STATE_VERSION
    assert migrated["briefs"] == {}
    assert migrated["awaiting_handoffs"] == []


def test_version_four_checkpoint_migrates_one_awaiting_handoff(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    state = module.empty_state()
    state["version"] = 4
    state["awaiting_handoff"] = {
        "room_name": "backlog",
        "request": "REVIEW_READY",
        "recipient_agent": "lens",
        "body": f"REVIEW_READY target={_review_target()}",
        "correlation": {"target": _review_target()},
    }
    state.pop("awaiting_handoffs")

    migrated = module.load_state(_write_json(tmp_path / "v4-state.json", state))

    assert migrated["version"] == module.STATE_VERSION
    assert migrated["awaiting_handoffs"] == [state["awaiting_handoff"]]


def test_version_five_checkpoint_starts_a_clean_thread_but_preserves_work(
    supervisor_module,
    tmp_path,
):
    module = supervisor_module
    state = module.empty_state()
    state["version"] = 5
    state["thread_id"] = "legacy-wait-thread"
    state["in_flight"] = [
        {
            "attention_id": "attn-" + "5" * 32,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]

    migrated = module.load_state(_write_json(tmp_path / "v5-state.json", state))

    assert migrated["version"] == module.STATE_VERSION
    assert migrated["thread_id"] is None
    assert migrated["in_flight"] == state["in_flight"]


def test_inspect_state_uses_runtime_migration_without_mutating_checkpoint(
    supervisor_module,
    tmp_path,
    capsys,
):
    module = supervisor_module
    state = module.empty_state()
    state["version"] = 5
    state["thread_id"] = "legacy-wait-thread"
    state["in_flight"] = [
        {
            "attention_id": "attn-" + "5" * 32,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    state_path = _write_json(tmp_path / "v5-state.json", state)
    before = state_path.read_bytes()

    assert module.main(["--inspect-state", str(state_path)]) == 0

    summary = json.loads(capsys.readouterr().out)
    assert summary == {
        "consecutive_failures": 0,
        "in_flight": 1,
        "owned_process": None,
        "safe_cursor": 0,
        "version": module.STATE_VERSION,
    }
    assert state_path.read_bytes() == before


def test_inspect_state_rejects_missing_checkpoint(supervisor_module, tmp_path, capsys):
    module = supervisor_module

    assert module.main(["--inspect-state", str(tmp_path / "missing.json")]) == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "supervisor state does not exist" in captured.err


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


def test_preflight_allows_mcp_timeout_below_external_wait(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path, tool_timeout=5)

    def api(path, **kwargs):
        if path == "/health":
            return {"agent_api": "ok"}
        return {"room_id": "room-1", "permissions": ["send", "receive"]}

    monkeypatch.setattr(module, "_api_json", api)

    assert module.preflight(_config(module, tmp_path)) == {"room-1": "backlog"}


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


def test_preflight_joins_factory_and_agent_rooms(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path)
    joined = []

    def api(path, **kwargs):
        if path == "/health":
            return {"agent_api": "ok"}
        joined.append(path)
        return {"room_id": f"room-{len(joined)}", "permissions": ["send", "receive"]}

    monkeypatch.setattr(module, "_api_json", api)

    rooms = module.preflight(_config(module, tmp_path, agent_room="forge-agent"))

    assert joined == [
        "/api/coord/rooms/backlog/join",
        "/api/coord/rooms/forge-agent/join",
    ]
    assert rooms == {"room-1": "backlog", "room-2": "forge-agent"}


def test_factory_preflight_hydrates_current_brief_for_restart(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path)
    state = module.empty_state()
    canonical = _resolved_brief("attn-" + "a" * 32)["object"]

    def api(path, **kwargs):
        if path == "/health":
            return {"agent_api": "ok"}
        return {
            "room_id": "room-1",
            "permissions": ["send", "receive"],
            "brief": canonical,
        }

    monkeypatch.setattr(module, "_api_json", api)

    room_ids = module.preflight(
        _factory_config(module, tmp_path, "owner"),
        state,
    )

    assert room_ids == {"room-1": "backlog"}
    assert state["briefs"]["backlog"]["markdown"] == "# Standing direction"


def test_factory_preflight_denies_brief_context_without_receive_authority(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    _stage_preflight(monkeypatch, module, tmp_path)
    state = module.empty_state()

    def api(path, **kwargs):
        if path == "/health":
            return {"agent_api": "ok"}
        return {
            "room_id": "room-1",
            "permissions": ["send"],
            "brief": _resolved_brief("attn-" + "b" * 32)["object"],
        }

    monkeypatch.setattr(module, "_api_json", api)

    with pytest.raises(module.SupervisorError, match="receive permission"):
        module.preflight(_factory_config(module, tmp_path, "owner"), state)
    assert state["briefs"] == {}


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

    previous_subreaper = module._set_subreaper()
    try:
        result = module.run_invocation(
            _config(module, tmp_path, startup_timeout_seconds=1),
            state,
            state_path,
            {"room-1": "backlog"},
            [],
        )
    finally:
        module._set_subreaper(previous_subreaper)

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
        "                'body':'TASK target=https://example.test/work/one assignee=forge','sequence':1}\n"
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
    monkeypatch.setattr(module, "_pidfd_open", lambda pid: 17)
    monkeypatch.setattr(module, "_process_start_time", lambda pid: "new-unrelated-start")
    monkeypatch.setattr(
        module,
        "_pidfd_send_signal",
        lambda pidfd, signal_number: sent.append((pidfd, signal_number)),
    )
    monkeypatch.setattr(module.os, "close", lambda pidfd: closed.append(pidfd))

    assert module._signal_pid_identity(4242, "old-owned-start", module.signal.SIGTERM) is False
    assert sent == []
    assert closed == [17]


def test_pidfd_syscall_fallback_without_cpython_wrappers(supervisor_module, monkeypatch):
    module = supervisor_module
    calls = []
    monkeypatch.delattr(module.os, "pidfd_open", raising=False)
    monkeypatch.delattr(module.signal, "pidfd_send_signal", raising=False)

    def syscall(number, *arguments):
        calls.append((number, arguments))
        return 17 if number == module.SYS_PIDFD_OPEN else 0

    monkeypatch.setattr(module, "_linux_syscall", syscall)

    assert module._pidfd_open(4242) == 17
    module._pidfd_send_signal(17, module.signal.SIGTERM)

    assert [number for number, _ in calls] == [
        module.SYS_PIDFD_OPEN,
        module.SYS_PIDFD_SEND_SIGNAL,
    ]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pidfd is Linux-specific")
def test_pidfd_syscall_fallback_reaches_linux_kernel(supervisor_module, monkeypatch):
    module = supervisor_module
    monkeypatch.delattr(module.os, "pidfd_open", raising=False)
    monkeypatch.delattr(module.signal, "pidfd_send_signal", raising=False)

    module._require_pidfd_support()


def test_restart_cleans_a_checkpointed_detached_child(supervisor_module, tmp_path):
    module = supervisor_module
    child = module.subprocess.Popen(["sleep", "60"], start_new_session=True)
    state = module.empty_state()
    state["thread_id"] = "interrupted-thread"
    state_path = tmp_path / "state.json"
    state["owned_process"] = {
        "pid": 999_999_999,
        "start_time": "1",
        "descendants": [{"pid": child.pid, "start_time": module._process_start_time(child.pid)}],
    }
    module.save_state(state_path, state)

    module.cleanup_stale_owned_process(state, state_path, grace=1)
    child.wait(timeout=2)

    persisted = module.load_state(state_path)
    assert persisted["owned_process"] is None
    assert persisted["thread_id"] is None


def test_restart_cleans_uncheckpointed_same_group_child(supervisor_module, tmp_path):
    module = supervisor_module
    child_pid_file = tmp_path / "same-group-child.pid"
    leader = module.subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import signal, subprocess, sys, time\n"
                "from pathlib import Path\n"
                "child = subprocess.Popen(['sleep', '60'])\n"
                "def stop(*_):\n"
                "    child.terminate()\n"
                "    child.wait()\n"
                "    raise SystemExit(0)\n"
                "signal.signal(signal.SIGTERM, stop)\n"
                "Path(sys.argv[1]).write_text(str(child.pid))\n"
                "while True:\n"
                "    time.sleep(1)\n"
            ),
            str(child_pid_file),
        ],
        start_new_session=True,
    )
    for _ in range(100):
        if child_pid_file.exists():
            break
        time.sleep(0.02)
    assert child_pid_file.exists()
    child_pid = int(child_pid_file.read_text())
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    state["owned_process"] = {
        "pid": leader.pid,
        "start_time": module._process_start_time(leader.pid),
        "descendants": [],
    }
    module.save_state(state_path, state)

    module.cleanup_stale_owned_process(state, state_path, grace=1)
    leader.wait(timeout=2)
    for _ in range(100):
        if not Path(f"/proc/{child_pid}").exists():
            break
        time.sleep(0.02)

    assert not Path(f"/proc/{child_pid}").exists()
    assert module.load_state(state_path)["owned_process"] is None


def test_restart_never_signals_group_for_reused_leader(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    state = module.empty_state()
    state_path = tmp_path / "state.json"
    state["owned_process"] = {
        "pid": 4242,
        "start_time": "old-owned-start",
        "descendants": [],
    }
    module.save_state(state_path, state)
    group_signals = []
    monkeypatch.setattr(module, "_open_pidfd_for_identity", lambda pid, start: None)
    monkeypatch.setattr(module, "_process_start_time", lambda pid: "new-unrelated-start")
    monkeypatch.setattr(
        module.os,
        "killpg",
        lambda pid, signal_number: group_signals.append((pid, signal_number)),
    )

    module.cleanup_stale_owned_process(state, state_path, grace=0)

    assert group_signals == []
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


def test_agent_room_receives_each_codex_stdout_event_and_coalesces_stderr_chunk(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    fake_codex = tmp_path / "fake-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-one'}), flush=True)\n"
        "print(json.dumps({'type':'turn.started'}), flush=True)\n"
        "__import__('sys').stderr.write('provider diagnostic one\\nprovider diagnostic two\\n')\n"
        "__import__('sys').stderr.flush()\n"
        "print(json.dumps({'type':'turn.completed'}), flush=True)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    sends = []

    def api_json(path, *, method="GET", body=None):
        sends.append((path, method, body))
        return {"sequence": len(sends)}

    monkeypatch.setattr(module, "_api_json", api_json)
    state = module.empty_state()
    state_path = tmp_path / "state.json"

    result = module.run_invocation(
        _config(module, tmp_path, agent_room="forge-agent"),
        state,
        state_path,
        {"room-1": "backlog", "room-2": "forge-agent"},
        [],
    )

    assert result.saw_turn_completed is True
    event_types = [json.loads(call[2]["body"])["type"] for call in sends]
    assert event_types.count("safeyolo.codex.stderr") == 1
    assert [event_type for event_type in event_types if event_type != "safeyolo.codex.stderr"] == [
        "thread.started",
        "turn.started",
        "turn.completed",
    ]
    stderr_call = sends[event_types.index("safeyolo.codex.stderr")]
    assert json.loads(stderr_call[2]["body"])["text"] == (
        "provider diagnostic one\nprovider diagnostic two\n"
    )
    assert all(call[0] == "/api/coord/rooms/forge-agent/send" for call in sends)
    assert all(call[2]["notify"] == "none" for call in sends)


def test_oversize_codex_event_is_one_head_tail_coord_message(supervisor_module):
    module = supervisor_module
    original = json.dumps(
        {
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "status": "completed",
                "command": "rg -n pattern /workspace",
                "aggregated_output": "HEAD-SENTINEL\n"
                + "x" * module.MAX_AGENT_ROOM_BODY_BYTES
                + "\nTAIL-SENTINEL",
            },
        },
        separators=(",", ":"),
    )

    bounded = module._bounded_agent_room_body(original)
    event = json.loads(bounded)

    assert len(bounded.encode()) <= module.MAX_AGENT_ROOM_BODY_BYTES
    assert event["type"] == "safeyolo.codex.oversize"
    assert event["original_type"] == "item.completed"
    assert event["original_bytes"] == len(original.encode())
    assert event["omitted_middle_bytes"] > 0
    assert event["sha256"] == hashlib.sha256(original.encode()).hexdigest()
    assert event["summary"]["type"] == "command_execution"
    assert event["summary"]["command"] == "rg -n pattern /workspace"
    assert "HEAD-SENTINEL" in event["head"]
    assert "TAIL-SENTINEL" in event["tail"]


def test_oversize_agent_room_event_does_not_abort_codex_turn(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    fake_codex = tmp_path / "fake-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-one'}), flush=True)\n"
        "print(json.dumps({'type':'turn.started'}), flush=True)\n"
        "print(json.dumps({'type':'item.completed','item':"
        "{'type':'command_execution','command':'rg -n broad-search',"
        "'aggregated_output':'x' * 300000,'status':'completed'}}), flush=True)\n"
        "print(json.dumps({'type':'turn.completed'}), flush=True)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    sends = []

    def api_json(path, *, method="GET", body=None):
        assert len(body["body"].encode()) <= module.MAX_AGENT_ROOM_BODY_BYTES
        sends.append((path, method, body))
        return {"sequence": len(sends)}

    monkeypatch.setattr(module, "_api_json", api_json)
    state = module.empty_state()

    result = module.run_invocation(
        _config(module, tmp_path, agent_room="lens-agent"),
        state,
        tmp_path / "state.json",
        {"room-1": "backlog", "room-2": "lens-agent"},
        [],
    )

    assert result.saw_turn_completed is True
    published = [json.loads(call[2]["body"]) for call in sends]
    oversize = [event for event in published if event["type"] == "safeyolo.codex.oversize"]
    assert len(oversize) == 1
    assert oversize[0]["summary"]["command"] == "rg -n broad-search"


def test_agent_room_publish_failure_does_not_abort_codex_turn(
    supervisor_module,
    tmp_path,
    monkeypatch,
    capsys,
):
    module = supervisor_module
    fake_codex = tmp_path / "fake-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "print(json.dumps({'type':'thread.started','thread_id':'thread-one'}), flush=True)\n"
        "print(json.dumps({'type':'turn.started'}), flush=True)\n"
        "print(json.dumps({'type':'turn.completed'}), flush=True)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    monkeypatch.setattr(
        module,
        "_api_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("coord unavailable")),
    )
    state = module.empty_state()

    result = module.run_invocation(
        _config(module, tmp_path, agent_room="lens-agent"),
        state,
        tmp_path / "state.json",
        {"room-1": "backlog", "room-2": "lens-agent"},
        [],
    )

    assert result.saw_turn_completed is True
    assert "cannot publish safeyolo.codex.stdout" in capsys.readouterr().err


def test_supervisor_room_event_is_best_effort(supervisor_module, tmp_path, monkeypatch, capsys):
    module = supervisor_module
    config = _config(module, tmp_path, agent_room="forge-agent")
    monkeypatch.setattr(
        module,
        "_api_json",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("coord unavailable")),
    )

    module._send_agent_room_event(config, "safeyolo.supervisor", event="started")

    assert "cannot publish safeyolo.supervisor" in capsys.readouterr().err


def test_main_publishes_supervisor_start_and_exit(supervisor_module, tmp_path, monkeypatch):
    module = supervisor_module
    config = _config(module, tmp_path, agent_room="forge-agent")
    events = []

    class Lock:
        def close(self):
            pass

    class FakeSupervisor:
        def __init__(self, *_args, **_kwargs):
            pass

        def cycle(self):
            return True

    monkeypatch.setattr(module.Config, "load", lambda _path: config)
    monkeypatch.setattr(module, "_lock_state", lambda _path: Lock())
    monkeypatch.setattr(module, "Supervisor", FakeSupervisor)
    monkeypatch.setattr(
        module,
        "_send_agent_room_event",
        lambda _config, event_type, **fields: events.append((event_type, fields)),
    )

    assert module.main(["--once"]) == 0
    assert events[0][0:2] == ("safeyolo.supervisor", {"event": "started", "pid": module.os.getpid()})
    assert events[-1] == ("safeyolo.supervisor", {"event": "exited", "exit_code": 0})


def test_signal_interrupt_carries_signal_number(supervisor_module):
    with pytest.raises(supervisor_module.SignalInterrupt) as caught:
        supervisor_module._interrupt_for_signal(supervisor_module.signal.SIGTERM, None)

    assert caught.value.signum == supervisor_module.signal.SIGTERM


def test_signal_during_invocation_discards_only_interrupted_thread(
    supervisor_module,
    tmp_path,
    monkeypatch,
):
    module = supervisor_module
    fake_codex = tmp_path / "fake-codex"
    fake_codex.write_text(
        "#!/usr/bin/env python3\n"
        "import time\n"
        "time.sleep(60)\n"
    )
    fake_codex.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CODEX_BIN", str(fake_codex))
    attention_id = "attn-" + "9" * 32
    state = module.empty_state()
    state["thread_id"] = "interrupted-thread"
    state["in_flight"] = [
        {
            "attention_id": attention_id,
            "room_name": "backlog",
            "sender_agent_name": "relay",
            "sender_agent_id": "agent-relay",
            "sequence": 11,
            "body": f"TASK target={WORK_ONE_TARGET} assignee=forge",
            "requires_terminal": True,
        }
    ]
    state_path = tmp_path / "state.json"
    module.save_state(state_path, state)

    def interrupt(*_args):
        raise module.SignalInterrupt(module.signal.SIGTERM)

    monkeypatch.setattr(module, "_checkpoint_owned_descendants", interrupt)

    with pytest.raises(module.SignalInterrupt):
        module.run_invocation(
            _config(module, tmp_path),
            state,
            state_path,
            {"room-1": "backlog"},
            [],
        )

    persisted = module.load_state(state_path)
    assert persisted["thread_id"] is None
    assert persisted["in_flight"][0]["attention_id"] == attention_id
    assert persisted["owned_process"] is None
