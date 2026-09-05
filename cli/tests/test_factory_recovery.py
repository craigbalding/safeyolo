"""Stopped-work recovery against real checkpoints and a disposable Coord server."""

from __future__ import annotations

import asyncio
import copy
import os
from types import SimpleNamespace

import pytest

from safeyolo import factory_recovery as recovery
from safeyolo.agents_store import save_agent
from safeyolo.coord import api, nats_client, nats_runtime
from safeyolo.coord.identity import new_operation_id
from safeyolo.factory_contract import FactoryContractError
from safeyolo.vm import get_agent_home_dir

TARGET = "https://example.test/issues/1"
OTHER = "https://example.test/issues/2"
REVIEW = "https://example.test/reviews/1/commits/abcdef"


def _pending(target=TARGET, room="backlog", digit="a"):
    return {
        "attention_id": "attn-" + digit * 32,
        "room_name": room,
        "sender_agent_name": "relay",
        "sender_agent_id": "ag-" + "b" * 32,
        "sequence": 12,
        "body": f"TASK target={target} assignee=forge\n\nDo the assigned work.",
        "requires_terminal": True,
    }


def _awaiting(target=TARGET, room="backlog", recipient="forge", request="TASK"):
    body = f"{request} target={target}"
    if request == "TASK":
        body += f" assignee={recipient}"
    return {
        "room_name": room, "request": request, "recipient_agent": recipient,
        "body": body, "correlation": {"target": target},
    }


@pytest.fixture
def stopped_factory(tmp_config_dir, tmp_path, nats_env, monkeypatch):
    nats_runtime.start_server(ready_timeout=8)
    nats_client.reset_for_tests()
    api.bootstrap()
    asyncio.run(api.create_room("backlog"))
    api.grant("backlog", "operator", "operator", operation_id=new_operation_id())
    supervisor = recovery._supervisor()
    monkeypatch.setattr(recovery, "_supervisor", lambda: supervisor)
    platform = SimpleNamespace(is_sandbox_running=lambda _name: False)
    monkeypatch.setattr(recovery, "get_platform", lambda: platform)
    payload = {"name": "sample", "room": "backlog", "roles": {}}
    states, paths = {}, {}
    for role, agent in (("coordinator", "relay"), ("owner", "forge"), ("reviewer", "lens")):
        workspace = tmp_path / f"{agent}-workspace"
        workspace.mkdir()
        (workspace / "keep.txt").write_text("unfinished work\n")
        save_agent(agent, {"folder": str(workspace)})
        payload["roles"][role] = {"agent": agent}
        path = get_agent_home_dir(agent) / ".safeyolo/codex-coord-supervisor-state.json"
        path.parent.mkdir(parents=True, mode=0o700)
        state = supervisor.empty_state()
        state.update(thread_id=f"{agent}-thread", safe_cursor=50, consecutive_failures=2)
        states[agent], paths[agent] = state, path
    states["relay"]["awaiting_handoffs"] = [_awaiting(), _awaiting(OTHER)]
    states["forge"]["in_flight"] = [_pending(), _pending(OTHER, digit="b"), _pending(room="old", digit="c")]
    states["forge"]["awaiting_handoffs"] = [_awaiting(REVIEW, recipient="lens", request="REVIEW_READY")]
    for agent, path in paths.items():
        supervisor.save_state(path, states[agent])
    return SimpleNamespace(payload=payload, supervisor=supervisor, states=states, paths=paths, platform=platform)


def _messages():
    return asyncio.run(api.read_room("backlog", "operator", "operator"))["messages"]


def test_release_preserves_unrelated_work_and_records_operator_action(stopped_factory, tmp_path):
    env = stopped_factory
    before = {name: path.read_bytes() for name, path in env.paths.items()}
    plans = []
    result = recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda plan: plans.append(plan) or True)
    assert "relay" in result and "forge" in result
    assert "target=" + TARGET in plans[0]
    relay = env.supervisor.load_state(env.paths["relay"])
    forge = env.supervisor.load_state(env.paths["forge"])
    assert relay["awaiting_handoffs"] == [_awaiting(OTHER)]
    assert forge["in_flight"] == env.states["forge"]["in_flight"][1:]
    assert forge["awaiting_handoffs"] == env.states["forge"]["awaiting_handoffs"]
    assert forge["safe_cursor"] == 50
    assert forge["consecutive_failures"] == 2
    assert forge["thread_id"] is None
    assert "attn-" + "a" * 32 in forge["recent_attention_ids"]
    assert env.paths["lens"].read_bytes() == before["lens"]
    for agent in ("relay", "forge"):
        backups = list(env.paths[agent].parent.glob("*.before-release-*.json"))
        assert len(backups) == 1 and backups[0].read_bytes() == before[agent]
    assert (tmp_path / "forge-workspace/keep.txt").read_text() == "unfinished work\n"
    messages = _messages()
    assert len(messages) == 2
    assert all(m["sender_kind"] == "operator" for m in messages)
    assert "release requested" in messages[0]["body"]
    assert "release completed" in messages[1]["body"]
    assert recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True).startswith("No matching")
    assert _messages() == messages


def test_release_can_select_old_room_without_touching_current_assignment(stopped_factory):
    env = stopped_factory
    asyncio.run(api.create_room("old"))
    api.grant("old", "operator", "operator", operation_id=new_operation_id())
    recovery.release_stopped_work(env.payload, "old", {TARGET}, lambda _: True)
    assert env.supervisor.load_state(env.paths["forge"])["in_flight"] == env.states["forge"]["in_flight"][:2]
    assert _messages() == []


@pytest.mark.parametrize("entry", ["home", "directory", "state", "lock"])
def test_release_rejects_redirected_host_paths(stopped_factory, tmp_path, entry):
    env = stopped_factory
    checkpoint = env.paths["forge"]
    outside = tmp_path / "outside"
    outside.mkdir()
    if entry in {"home", "directory"}:
        original = checkpoint.parent.parent if entry == "home" else checkpoint.parent
        original.rename(outside / "moved")
        original.symlink_to(outside / "moved", target_is_directory=True)
    else:
        original = checkpoint if entry == "state" else checkpoint.with_name(checkpoint.name + ".lock")
        target = outside / "sentinel"
        target.write_bytes(checkpoint.read_bytes() if entry == "state" else b"keep lock\n")
        if original.exists():
            original.unlink()
        original.symlink_to(target)
    before = {str(path.relative_to(outside)): path.read_bytes() for path in outside.rglob("*") if path.is_file()}
    with pytest.raises(FactoryContractError, match="unsafe checkpoint"):
        recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    after = {str(path.relative_to(outside)): path.read_bytes() for path in outside.rglob("*") if path.is_file()}
    assert after == before
    assert _messages() == []


@pytest.mark.parametrize("kind", ["hardlink", "fifo"])
@pytest.mark.parametrize("entry", ["state", "lock"])
def test_release_rejects_nonprivate_checkpoint_entries(stopped_factory, tmp_path, kind, entry):
    env = stopped_factory
    checkpoint = env.paths["forge"]
    original = checkpoint if entry == "state" else checkpoint.with_name(checkpoint.name + ".lock")
    target = tmp_path / "sentinel"
    target.write_bytes(checkpoint.read_bytes())
    if original.exists():
        original.unlink()
    if kind == "hardlink":
        os.link(target, original)
    else:
        os.mkfifo(original)
    before = target.read_bytes()
    with pytest.raises(FactoryContractError, match="unsafe checkpoint"):
        recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    assert target.read_bytes() == before
    assert _messages() == []


@pytest.mark.parametrize("failure", ["running", "state-lock", "invalid-state", "declined"])
def test_release_preconditions_do_not_partially_clear_work(stopped_factory, failure):
    env = stopped_factory
    lock = None
    if failure == "running":
        env.platform.is_sandbox_running = lambda name: name == "forge"
    elif failure == "state-lock":
        lock = env.supervisor._lock_state(env.paths["relay"])
    elif failure == "invalid-state":
        env.paths["relay"].write_text("not json")
    before = {name: path.read_bytes() for name, path in env.paths.items()}
    try:
        if failure == "declined":
            assert "cancelled" in recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: False)
        else:
            with pytest.raises((FactoryContractError, env.supervisor.SupervisorError)):
                recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    finally:
        if lock:
            lock.close()
    assert {name: path.read_bytes() for name, path in env.paths.items()} == before
    assert _messages() == []


def test_unavailable_coord_does_not_release_work(stopped_factory, monkeypatch):
    env = stopped_factory
    before = {name: path.read_bytes() for name, path in env.paths.items()}

    async def fail(*args, **kwargs):
        raise nats_client.NatsUnavailable("offline")

    monkeypatch.setattr(api, "send", fail)
    with pytest.raises(FactoryContractError, match="changed agents=none"):
        recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    assert {name: path.read_bytes() for name, path in env.paths.items()} == before


def test_partial_write_failure_can_resume_without_touching_other_work(stopped_factory, monkeypatch):
    env = stopped_factory
    save = env.supervisor.save_state

    def fail_second(path, state):
        if path == env.paths["relay"]:
            raise OSError("disk error")
        save(path, state)

    monkeypatch.setattr(env.supervisor, "save_state", fail_second)
    with pytest.raises(FactoryContractError, match="changed agents=forge"):
        recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    assert len(_messages()) == 1  # Request recorded; completion was not claimed.
    forge_after = env.paths["forge"].read_bytes()
    monkeypatch.setattr(env.supervisor, "save_state", save)
    recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    assert env.paths["forge"].read_bytes() == forge_after
    assert env.supervisor.load_state(env.paths["relay"])["awaiting_handoffs"] == [_awaiting(OTHER)]


def test_multiple_exact_targets_and_decoder_roundtrip(stopped_factory):
    env = stopped_factory
    original = copy.deepcopy(env.states["forge"])
    lens = copy.deepcopy(env.states["lens"])
    request = _pending(REVIEW, digit="d")
    request.update(body=f"REVIEW_READY target={REVIEW}", sender_agent_name="forge")
    lens["in_flight"] = [request]
    env.supervisor.save_state(env.paths["lens"], lens)
    recovery.release_stopped_work(env.payload, "backlog", {TARGET, REVIEW}, lambda _: True)
    updated = env.supervisor.load_state(env.paths["forge"])
    assert updated["awaiting_handoffs"] == []
    assert updated["in_flight"] == original["in_flight"][1:]
    assert env.supervisor.load_state(env.paths["lens"])["in_flight"] == []


def test_release_cli_uses_exact_targets_and_old_room_option(stopped_factory, cli_runner, monkeypatch):
    from safeyolo.cli import app

    env = stopped_factory
    monkeypatch.setattr("safeyolo.commands.factory.load_approved_snapshot", lambda _: ("snapshot", None, env.payload))
    result = cli_runner.invoke(
        app, ["factory", "release", "sample", "--room", "backlog", "--target", TARGET, "--target", REVIEW, "--yes"]
    )
    assert result.exit_code == 0, result.output
    assert "Released checkpointed work" in result.output
    assert env.supervisor.load_state(env.paths["forge"])["awaiting_handoffs"] == []


def test_release_cli_rejects_relative_target_without_changes(stopped_factory, cli_runner, monkeypatch):
    from safeyolo.cli import app

    env = stopped_factory
    monkeypatch.setattr("safeyolo.commands.factory.load_approved_snapshot", lambda _: ("snapshot", None, env.payload))
    before = {name: path.read_bytes() for name, path in env.paths.items()}
    result = cli_runner.invoke(app, ["factory", "release", "sample", "--target", "issue/1", "--yes"])
    assert result.exit_code == 1
    assert "exact absolute target URLs" in result.output
    assert {name: path.read_bytes() for name, path in env.paths.items()} == before


def test_checkpoint_changed_during_confirmation_is_not_overwritten(stopped_factory):
    env = stopped_factory
    changed = copy.deepcopy(env.states["relay"])
    changed["safe_cursor"] += 1

    def confirm(_description):
        env.supervisor.save_state(env.paths["relay"], changed)
        return True

    with pytest.raises(FactoryContractError, match="checkpoint changed"):
        recovery.release_stopped_work(env.payload, "backlog", {TARGET}, confirm)
    assert env.supervisor.load_state(env.paths["relay"]) == changed
    assert env.supervisor.load_state(env.paths["forge"]) == env.states["forge"]
    assert _messages() == []


def test_failed_completion_record_reports_released_state_without_false_success(stopped_factory, monkeypatch):
    env = stopped_factory
    send = api.send
    calls = 0

    async def fail_completion(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise nats_client.NatsUnavailable("offline after release")
        return await send(*args, **kwargs)

    monkeypatch.setattr(api, "send", fail_completion)
    with pytest.raises(FactoryContractError, match="changed agents=forge,relay"):
        recovery.release_stopped_work(env.payload, "backlog", {TARGET}, lambda _: True)
    assert len(_messages()) == 1
    assert env.supervisor.load_state(env.paths["relay"])["awaiting_handoffs"] == [_awaiting(OTHER)]
