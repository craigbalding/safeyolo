"""Acceptance tests for declarative supervised factory contracts."""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import time
from pathlib import Path
from unittest.mock import create_autospec

import pytest
from click import unstyle

from safeyolo.cli import app
from safeyolo.factory_contract import (
    FactoryContractError,
    approve_snapshot,
    load_approved_snapshot,
    load_factory_file,
)
from safeyolo.factory_doctor import FactoryDoctorCheck, FactoryDoctorReport
from safeyolo.platform import AgentPlatform

BACKLOG_COORDINATOR_CONTRACT = Path(__file__).parents[2] / "docs/factories/backlog-coordinator.md"
BACKLOG_REVIEWER_CONTRACT = Path(__file__).parents[2] / "docs/agent-roles/independent-reviewer.md"


def _passing_factory_report(name: str = "backlog") -> FactoryDoctorReport:
    return FactoryDoctorReport(
        name,
        (FactoryDoctorCheck("PASS", "operational-preflight", "all checks pass"),),
    )


def test_backlog_coordinator_status_contract_is_low_noise():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())

    assert "Send an ordinary answer with no agent attention." in contract
    assert "Do not expect a new `ACCEPTED` after a Lens disposition." in contract
    assert "report that the updated candidate is pending" in contract


def test_backlog_coordinator_contract_owns_proactive_flow_and_backfill():
    contract = " ".join(BACKLOG_COORDINATOR_CONTRACT.read_text().split())

    assert "Relay owns productive and resilient factory flow." in contract
    assert "Do not require the operator to name each work item." in contract
    assert "When Forge has useful capacity" in contract
    assert "When Lens has useful capacity" in contract
    assert "Treat an actionable `BLOCKED` or `FAILED` response as coordinator work." in contract
    assert "the factory does not require a brief" in contract


def test_backlog_reviewer_contract_binds_install_trust_and_complexity_checks():
    contract = " ".join(BACKLOG_REVIEWER_CONTRACT.read_text().split())

    assert "trusted base revision's tracked lockfiles" in contract
    assert "it does not grant itself standing approval" in contract
    assert "Run deterministic post-change quality analysis" in contract
    assert "--select C901,PLR0911,PLR0912,PLR0913,PLR0915" in contract
    assert "A tool finding is evidence, not an automatic veto" in contract


def _factory_file(tmp_path: Path, *, name: str = "backlog", extra: str = "") -> Path:
    (tmp_path / "coordinator.md").write_text("# Coordinator\n\nDelegate exact tasks.\n")
    (tmp_path / "owner.md").write_text("# Owner\n\nOwn the issue.\n")
    (tmp_path / "reviewer.md").write_text("# Reviewer\n\nReview independently.\n")
    path = tmp_path / "backlog.toml"
    path.write_text(
        'schema = "safeyolo.factory/v1"\n'
        f'name = "{name}"\n'
        'room = "backlog"\n\n'
        '[operator_input]\n'
        'to = "coordinator"\n'
        'types = ["ACTIVATE", "PAUSE", "RESUME", "PRIORITY", "NEXT", "DIRECTION"]\n\n'
        '[roles.coordinator]\nagent = "relay"\ncontract = "coordinator.md"\n\n'
        '[roles.owner]\nagent = "forge"\ncontract = "owner.md"\n\n'
        '[roles.reviewer]\nagent = "lens"\ncontract = "reviewer.md"\n\n'
        '[[handoffs]]\nrequest = "TASK"\nfrom = "coordinator"\nto = "owner"\n'
        'responses = ["DONE", "BLOCKED", "FAILED"]\n'
        'response_to = ["coordinator"]\n\n'
        '[[handoffs]]\nrequest = "TASK"\nfrom = "coordinator"\nto = "reviewer"\n'
        'responses = ["DONE", "BLOCKED", "FAILED"]\n'
        'response_to = ["coordinator"]\n\n'
        '[[handoffs]]\nrequest = "REVIEW_READY"\nfrom = "owner"\nto = "reviewer"\n'
        'responses = ["READY", "CHANGES_REQUIRED", "BLOCKED"]\n'
        'response_to = ["owner", "coordinator"]\n' + extra
    )
    return path


def test_factory_check_resolves_roles_handoffs_and_contract_hashes(cli_runner, tmp_path):
    path = _factory_file(tmp_path)

    result = cli_runner.invoke(app, ["factory", "check", str(path)])
    explanation = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert "factory=backlog schema=safeyolo.factory/v1 room=backlog" in result.output
    assert "role=owner agent=forge contract=owner.md" in result.output
    assert f"source={tmp_path / 'owner.md'}" in result.output
    assert "bytes=24" in result.output
    assert "sha256=" in result.output
    assert "operator_input=operator to=coordinator" in result.output
    assert "handoff=TASK from=coordinator to=reviewer" in result.output
    assert "handoff=REVIEW_READY from=owner to=reviewer" in result.output
    assert "response_to=owner,coordinator" in result.output
    assert "Approval creates an immutable snapshot." in explanation
    assert (
        "Inspect those files directly; SafeYolo does not summarize"
        in explanation
    )
    assert "The admitted input words are not workflow definitions." in explanation
    assert "separate live operator state" in explanation
    assert (
        "does not inspect live room state, grants, brief revision, or worker health"
        in explanation
    )
    assert "does not select work or prove live eligibility or readiness" in explanation
    assert "Read the bound role contract to determine intake behavior" in explanation
    assert "does not by itself disable proactive intake" in explanation
    assert "safeyolo coord brief show backlog" in explanation
    assert (
        "safeyolo coord brief set backlog --file BRIEF.md "
        "--expected-revision REVISION"
        in explanation
    )
    assert "safeyolo factory doctor backlog" in explanation


def test_factory_run_help_exposes_fresh_setup_order(cli_runner):
    result = cli_runner.invoke(app, ["factory", "run", "--help"])
    output = " ".join(unstyle(result.output).split())

    assert result.exit_code == 0, result.output
    assert "safeyolo agent add AGENT FOLDER --host-script @codex --no-run" in output
    assert "logged in to Codex with a ChatGPT subscription" in output
    assert "authentication and config into the agent home" in output
    assert output.index("factory check") < output.index("factory approve") < output.index("factory run NAME")


def test_factory_approve_requires_approval_and_stores_immutable_snapshot(
    cli_runner,
    tmp_path,
    tmp_config_dir,
):
    path = _factory_file(tmp_path)

    denied = cli_runner.invoke(app, ["factory", "approve", str(path)], input="n\n")
    assert denied.exit_code == 1
    assert not (tmp_config_dir / "factories").exists()

    approved = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert approved.exit_code == 0, approved.output
    identifier, snapshot_path, payload = load_approved_snapshot("backlog")
    assert (snapshot_path.parents[1] / "approved").read_text() == f"{identifier}\n"
    assert not (snapshot_path.parents[1] / "active").exists()
    assert snapshot_path.name == f"{identifier}.json"
    assert snapshot_path.stat().st_mode & 0o777 == 0o600
    assert payload["roles"]["owner"]["contract_text"] == "# Owner\n\nOwn the issue.\n"
    assert payload["handoffs"][2]["response_to"] == ["owner", "coordinator"]
    first = snapshot_path.read_bytes()

    repeated = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert repeated.exit_code == 0
    assert snapshot_path.read_bytes() == first

    compatibility = cli_runner.invoke(app, ["factory", "apply", str(path), "--yes"])
    assert compatibility.exit_code == 0, compatibility.output
    assert "deprecated; use factory approve" in compatibility.output
    assert snapshot_path.read_bytes() == first


def test_legacy_active_pointer_is_read_without_mutation(tmp_path, tmp_config_dir):
    from safeyolo.factory_contract import load_active_snapshot

    identifier, snapshot_path = approve_snapshot(load_factory_file(_factory_file(tmp_path)))
    root = snapshot_path.parents[1]
    (root / "approved").unlink()
    (root / "active").write_text(identifier + "\n")
    before = (root / "active").read_bytes()

    loaded_identifier, loaded_path, _payload = load_active_snapshot("backlog")

    assert loaded_identifier == identifier
    assert loaded_path == snapshot_path
    assert (root / "active").read_bytes() == before
    assert not (root / "approved").exists()


@pytest.mark.parametrize("name", [".", ".."])
def test_factory_approve_rejects_dot_path_names(cli_runner, tmp_path, tmp_config_dir, name):
    path = _factory_file(tmp_path, name=name)

    result = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])

    assert result.exit_code == 1
    assert "one simple name" in result.output
    assert not (tmp_config_dir / "factories").exists()


def test_factory_snapshot_storage_rejects_a_symlink_escape(tmp_path, tmp_config_dir):
    from safeyolo.factory_contract import approve_snapshot

    outside = tmp_path / "outside"
    outside.mkdir()
    factories = tmp_config_dir / "factories"
    factories.mkdir()
    (factories / "backlog").symlink_to(outside, target_is_directory=True)

    with pytest.raises(FactoryContractError, match="factory path escapes"):
        approve_snapshot(load_factory_file(_factory_file(tmp_path)))

    assert list(outside.iterdir()) == []


def test_factory_run_uses_only_the_approved_verified_snapshot(
    cli_runner,
    tmp_path,
    tmp_config_dir,
    monkeypatch,
):
    path = _factory_file(tmp_path)
    approved = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert approved.exit_code == 0
    calls = []
    monkeypatch.setattr(
        "safeyolo.commands.factory._run_snapshot",
        lambda snapshot_path, payload: calls.append((snapshot_path, payload)),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory._wait_for_operational_preflight",
        lambda _name: _passing_factory_report(),
    )

    result = cli_runner.invoke(app, ["factory", "run", "backlog"])

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    assert calls[0][1]["name"] == "backlog"
    assert calls[0][1]["roles"]["reviewer"]["agent"] == "lens"
    assert "snapshot_path=" in result.output
    assert "operator_input=operator to=coordinator" in result.output


def test_factory_run_preserves_each_agents_local_codex_auth(
    cli_runner,
    tmp_path,
    tmp_config_dir,
    monkeypatch,
):
    from safeyolo.agents_store import save_agent
    from safeyolo.vm import get_agent_home_dir

    operator_home = tmp_path / "operator"
    operator_codex = operator_home / ".codex"
    operator_codex.mkdir(parents=True)
    (operator_codex / "auth.json").write_text('{"owner":"operator"}\n')
    monkeypatch.setenv("HOME", str(operator_home))

    expected_auth = {}
    for index, name in enumerate(("relay", "forge", "lens"), start=1):
        folder = tmp_path / f"{name}-workspace"
        folder.mkdir()
        save_agent(name, {"agent_id": f"ag-{index:032x}", "folder": str(folder)})
        auth = get_agent_home_dir(name) / ".codex/auth.json"
        auth.parent.mkdir(parents=True)
        expected_auth[name] = f'{{"owner":"{name}"}}\n'
        auth.write_text(expected_auth[name])

    monkeypatch.setattr("safeyolo.commands.factory._run_agent", lambda *args, **kwargs: 0)
    monkeypatch.setattr("safeyolo.commands.factory.coord_nats.start_server", lambda **_kwargs: 123)
    monkeypatch.setattr("safeyolo.commands.factory.coord_api.bootstrap", lambda: "sy-test")
    monkeypatch.setattr(
        "safeyolo.commands.factory._ensure_factory_rooms",
        lambda _room, _names: None,
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory._wait_for_operational_preflight",
        lambda _name: _passing_factory_report(),
    )
    path = _factory_file(tmp_path)
    approved = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert approved.exit_code == 0, approved.output

    result = cli_runner.invoke(app, ["factory", "run", "backlog"])

    assert result.exit_code == 0, result.output
    for name, expected in expected_auth.items():
        assert (get_agent_home_dir(name) / ".codex/auth.json").read_text() == expected


def test_factory_run_executes_staged_worker_commands(
    cli_runner,
    tmp_path,
    tmp_config_dir,
    monkeypatch,
):
    """Exercise real factory and agent launch logic with small shell workers."""
    from safeyolo.agents_store import save_agent
    from safeyolo.vm import get_agent_home_dir, get_agent_status_dir

    names = ("relay", "forge", "lens")
    running: set[str] = set()
    coord_ready = False
    homes: dict[str, Path] = {}
    markers: dict[str, Path] = {}
    rootfs: dict[str, Path] = {}

    for index, name in enumerate(names, start=1):
        workspace = tmp_path / f"{name}-workspace"
        workspace.mkdir()
        save_agent(name, {"agent_id": f"ag-{index:032x}", "folder": str(workspace)})
        homes[name] = get_agent_home_dir(name)
        homes[name].mkdir(parents=True)
        markers[name] = tmp_path / f"{name}.pid"
        rootfs[name] = tmp_path / f"{name}-rootfs"
        rootfs[name].mkdir()

    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.agent_rootfs_path.side_effect = lambda name: rootfs[name]
    platform.is_sandbox_running.side_effect = lambda name: name in running
    platform.setup_networking.side_effect = lambda index: {
        "host_ip": "127.0.0.1",
        "guest_ip": f"10.200.0.{index + 1}",
        "attribution_ip": f"10.200.0.{index + 1}",
        "subnet": None,
        "needs_bridge_socket": False,
    }

    def start_sandbox(**kwargs):
        assert coord_ready
        name = kwargs["name"]
        running.add(name)
        status = get_agent_status_dir(name)
        status.mkdir(parents=True, exist_ok=True)
        (status / "per-run-started").write_text("")
        return os.getpid()

    def stop_sandbox(name):
        running.discard(name)

    def stage_worker(*, name, **_kwargs):
        command = homes[name] / ".safeyolo-command"
        command.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$$\" > {shlex.quote(str(markers[name]))}\n"
            "trap 'exit 0' TERM INT\n"
            "while :; do sleep 1; done\n"
        )
        command.chmod(0o755)

    def exec_in_sandbox(name, command, user="agent", interactive=True):
        assert user == "agent"
        assert interactive is False
        local_command = command.replace(
            "/home/agent/.safeyolo-command",
            shlex.quote(str(homes[name] / ".safeyolo-command")),
        )
        env = {**os.environ, "HOME": str(homes[name])}
        return subprocess.run(
            ["bash", "-c", local_command],
            env=env,
            timeout=5,
            check=False,
        ).returncode

    def start_command_supervisor(name, command):
        # The factory test uses a fake platform, so exercise the new
        # host-supervisor boundary with a local equivalent of its sandbox
        # command rather than invoking the real runsc platform.
        local_command = command.replace(
            "/home/agent/.safeyolo-command",
            shlex.quote(str(homes[name] / ".safeyolo-command")),
        )
        env = {**os.environ, "HOME": str(homes[name])}
        worker = subprocess.Popen(
            ["bash", "-c", local_command],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pids.append(worker.pid)

    platform.start_sandbox.side_effect = start_sandbox
    platform.stop_sandbox.side_effect = stop_sandbox
    platform.exec_in_sandbox.side_effect = exec_in_sandbox

    monkeypatch.setattr("safeyolo.platform.get_platform", lambda: platform)
    monkeypatch.setattr("safeyolo.commands.agent.is_proxy_running", lambda: True)
    monkeypatch.setattr(
        "safeyolo.commands.agent.reserve_agent_network_slot",
        lambda name: names.index(name),
    )
    monkeypatch.setattr("safeyolo.commands.agent._update_agent_map", lambda *args, **kwargs: None)
    monkeypatch.setattr("safeyolo.commands.agent.write_event", lambda *args, **kwargs: None)
    monkeypatch.setattr("safeyolo.commands.agent.prepare_config_share", lambda **kwargs: None)
    monkeypatch.setattr(
        "safeyolo.sockets.path_for",
        lambda name, _ip: tmp_path / f"{name}.sock",
    )
    monkeypatch.setattr("safeyolo.commands.factory._run_host_script_for_agent", stage_worker)
    monkeypatch.setattr(
        "safeyolo.agent_command_supervisor.start_command_supervisor",
        start_command_supervisor,
    )

    def start_coord(*, ready_timeout):
        nonlocal coord_ready
        assert ready_timeout == 10.0
        coord_ready = True
        return 123

    monkeypatch.setattr("safeyolo.commands.factory.coord_nats.start_server", start_coord)
    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_api.bootstrap",
        lambda: "sy-test" if coord_ready else pytest.fail("coord bootstrap preceded runtime"),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory._ensure_factory_rooms",
        lambda _room, _names: None,
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory._wait_for_operational_preflight",
        lambda _name: _passing_factory_report(),
    )

    path = _factory_file(tmp_path)
    approved = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert approved.exit_code == 0, approved.output

    pids: list[int] = []
    try:
        result = cli_runner.invoke(app, ["factory", "run", "backlog"])

        assert result.exit_code == 0, result.output
        assert coord_ready
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not all(marker.exists() for marker in markers.values()):
            time.sleep(0.01)
        assert all(marker.exists() for marker in markers.values())
        pids = [int(marker.read_text()) for marker in markers.values()]
        for pid in pids:
            os.kill(pid, 0)
    finally:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def test_factory_run_does_not_boot_workers_without_coord(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "roles": {
            "coordinator": {"agent": "relay"},
            "owner": {"agent": "forge"},
            "reviewer": {"agent": "lens"},
        },
    }
    launched: list[str] = []

    monkeypatch.setattr(
        "safeyolo.commands.factory.load_agent",
        lambda name: {"folder": str(workspace)},
    )
    monkeypatch.setattr("safeyolo.commands.factory._check_project_ownership", lambda *_args: None)
    monkeypatch.setattr("safeyolo.commands.factory._run_host_script_for_agent", lambda **_kwargs: None)
    monkeypatch.setattr("safeyolo.commands.factory.mutate_agent", lambda *_args: None)
    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_nats.start_server",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("nats unavailable")),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory._run_agent",
        lambda name, **_kwargs: launched.append(name) or 0,
    )

    from safeyolo.commands.factory import _run_snapshot

    with pytest.raises(FactoryContractError, match="Coord runtime failed before room/grant provisioning"):
        _run_snapshot(tmp_path / "snapshot.json", payload)

    assert launched == []


def test_factory_run_does_not_boot_workers_when_room_provisioning_fails(
    tmp_path,
    monkeypatch,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "room": "backlog",
        "roles": {
            "coordinator": {"agent": "relay"},
            "owner": {"agent": "forge"},
            "reviewer": {"agent": "lens"},
        },
    }
    launched: list[str] = []

    monkeypatch.setattr(
        "safeyolo.commands.factory.load_agent",
        lambda name: {"folder": str(workspace)},
    )
    monkeypatch.setattr("safeyolo.commands.factory._check_project_ownership", lambda *_args: None)
    monkeypatch.setattr("safeyolo.commands.factory._run_host_script_for_agent", lambda **_kwargs: None)
    monkeypatch.setattr("safeyolo.commands.factory.mutate_agent", lambda *_args: None)
    monkeypatch.setattr("safeyolo.commands.factory.coord_nats.start_server", lambda **_kwargs: 123)
    monkeypatch.setattr("safeyolo.commands.factory.coord_api.bootstrap", lambda: "sy-test")
    monkeypatch.setattr(
        "safeyolo.commands.factory._ensure_factory_rooms",
        lambda _room, _names: (_ for _ in ()).throw(RuntimeError("grant failed")),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory._run_agent",
        lambda name, **_kwargs: launched.append(name) or 0,
    )

    from safeyolo.commands.factory import _run_snapshot

    with pytest.raises(FactoryContractError, match="Coord room/grant provisioning failed"):
        _run_snapshot(tmp_path / "snapshot.json", payload)

    assert launched == []


def test_factory_run_missing_agent_prints_ordered_executable_recovery(
    cli_runner,
    tmp_path,
    tmp_config_dir,
):
    path = _factory_file(tmp_path)
    approved = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert approved.exit_code == 0, approved.output

    result = cli_runner.invoke(app, ["factory", "run", "backlog"])
    output = " ".join(result.output.split())

    assert result.exit_code == 1, result.output
    assert "Started factory" not in result.output
    assert 'safeyolo agent add relay "$PWD" --host-script @codex --no-run' in output
    assert "logged in to Codex with a ChatGPT subscription" in output
    assert output.index("agent add relay") < output.index("factory check")
    assert output.index("factory check") < output.index("factory approve") < output.index("factory run backlog")


def test_factory_run_requires_operational_preflight_before_success(
    cli_runner,
    tmp_path,
    tmp_config_dir,
    monkeypatch,
):
    path = _factory_file(tmp_path)
    approved = cli_runner.invoke(app, ["factory", "approve", str(path), "--yes"])
    assert approved.exit_code == 0, approved.output

    report = FactoryDoctorReport(
        "backlog",
        (FactoryDoctorCheck("FAIL", "supervisor", "role supervisor is not running"),),
    )
    monkeypatch.setattr("safeyolo.commands.factory._run_snapshot", lambda *_args: None)
    monkeypatch.setattr("safeyolo.commands.factory.inspect_factory", lambda _name: report)
    monkeypatch.setattr("safeyolo.commands.factory._FACTORY_PREFLIGHT_TIMEOUT_SECONDS", 0)

    result = cli_runner.invoke(app, ["factory", "run", "backlog"])

    assert result.exit_code == 1, result.output
    assert "Started factory" not in result.output
    assert "operational preflight did not pass" in result.output
    assert "safeyolo factory doctor backlog" in result.output
    assert "safeyolo factory run backlog" in result.output


def test_factory_run_waits_for_supervisors_then_accepts_pass(
    monkeypatch,
):
    from safeyolo.commands.factory import _wait_for_operational_preflight

    reports = iter(
        (
            FactoryDoctorReport(
                "backlog",
                (FactoryDoctorCheck("WARN", "supervisor", "starting"),),
            ),
            _passing_factory_report(),
        )
    )
    monkeypatch.setattr("safeyolo.commands.factory.inspect_factory", lambda _name: next(reports))
    monkeypatch.setattr("safeyolo.commands.factory.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("safeyolo.commands.factory._FACTORY_PREFLIGHT_TIMEOUT_SECONDS", 1)

    assert _wait_for_operational_preflight("backlog").status == "PASS"


def test_factory_ensures_shared_and_private_rooms_before_workers_start(monkeypatch):
    from safeyolo.commands.factory import _ensure_factory_rooms

    created = []
    grants = []

    async def create_room(name):
        created.append(name)
        return f"room-{name}"

    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_api.list_rooms",
        lambda: [{"name": "relay-agent"}],
    )
    monkeypatch.setattr("safeyolo.commands.factory.coord_api.create_room", create_room)
    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_api.grant",
        lambda room, kind, principal, **kwargs: grants.append((room, kind, principal)),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory.get_or_mint_agent_id",
        lambda name: f"id-{name}",
    )

    _ensure_factory_rooms("backlog", iter(("relay", "forge")))

    assert created == ["backlog", "forge-agent"]
    assert grants == [
        ("backlog", "operator", "operator"),
        ("backlog", "agent", "id-relay"),
        ("backlog", "agent", "id-forge"),
        ("relay-agent", "agent", "id-relay"),
        ("relay-agent", "operator", "operator"),
        ("forge-agent", "agent", "id-forge"),
        ("forge-agent", "operator", "operator"),
    ]


def test_factory_reuses_existing_shared_room_and_preserves_other_grants(monkeypatch):
    from safeyolo.commands.factory import _ensure_factory_rooms

    created = []
    grants = []

    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_api.list_rooms",
        lambda: [{"name": "backlog"}, {"name": "relay-agent"}],
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_api.create_room",
        lambda name: created.append(name),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory.coord_api.grant",
        lambda room, kind, principal, **kwargs: grants.append((room, kind, principal)),
    )
    monkeypatch.setattr(
        "safeyolo.commands.factory.get_or_mint_agent_id",
        lambda name: f"id-{name}",
    )

    _ensure_factory_rooms("backlog", iter(("relay",)))

    assert created == []
    assert grants[:2] == [
        ("backlog", "operator", "operator"),
        ("backlog", "agent", "id-relay"),
    ]


def test_factory_room_cannot_reuse_a_bound_agents_private_room(
    cli_runner,
    tmp_path,
):
    path = _factory_file(tmp_path)
    path.write_text(path.read_text().replace('room = "backlog"', 'room = "relay-agent"'))

    result = cli_runner.invoke(app, ["factory", "check", str(path)])

    assert result.exit_code == 1
    assert "conflicts with a bound" in result.output
    assert "agent's private room" in result.output


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda raw: raw.replace('name = "backlog"', 'name = "backlog"\nunknown = true'), "unknown"),
        (lambda raw: raw.replace('agent = "lens"', 'agent = "forge"'), "more than one role"),
        (lambda raw: raw.replace('request = "REVIEW_READY"', 'request = "review-ready"'), "uppercase"),
        (lambda raw: raw.replace('to = "reviewer"', 'to = "missing"'), "unknown role"),
        (
            lambda raw: raw.replace(
                'response_to = ["coordinator"]',
                'response_to = ["reviewer"]',
                1,
            ),
            "must include the source role",
        ),
        (
            lambda raw: raw.replace(
                'response_to = ["coordinator"]',
                'response_to = ["coordinator", "coordinator"]',
                1,
            ),
            "contains a duplicate",
        ),
    ],
)
def test_factory_contract_rejects_unknown_or_ambiguous_authority(tmp_path, mutation, message):
    path = _factory_file(tmp_path)
    path.write_text(mutation(path.read_text()))

    with pytest.raises(FactoryContractError, match=message):
        load_factory_file(path)


def test_approved_snapshot_rejects_tampering(tmp_path, tmp_config_dir):
    from safeyolo.factory_contract import approve_snapshot

    identifier, snapshot_path = approve_snapshot(load_factory_file(_factory_file(tmp_path)))
    payload = json.loads(snapshot_path.read_text())
    payload["room"] = "other"
    snapshot_path.write_text(json.dumps(payload))

    with pytest.raises(FactoryContractError, match="content hash"):
        load_approved_snapshot("backlog")
    assert identifier in snapshot_path.name


def test_factory_rejects_missing_operator_input_and_unreachable_roles(tmp_path):
    path = _factory_file(tmp_path)
    source = path.read_text()
    start = source.index("[operator_input]")
    end = source.index("[roles.coordinator]")
    path.write_text(source[:start] + source[end:])
    with pytest.raises(FactoryContractError, match="must declare operator_input"):
        load_factory_file(path)

    path = _factory_file(tmp_path)
    path.write_text(path.read_text().replace('to = "coordinator"', 'to = "owner"', 1))
    with pytest.raises(FactoryContractError, match="unreachable from operator_input.to: coordinator"):
        load_factory_file(path)


def test_factory_binds_exact_utf8_contract_bytes(tmp_path):
    path = _factory_file(tmp_path)
    encoded = b"# Owner\r\n\r\nExact bytes.\r\n"
    (tmp_path / "owner.md").write_bytes(encoded)

    contract = load_factory_file(path)
    owner = next(role for role in contract.roles if role.name == "owner")

    assert owner.contract_bytes == len(encoded)
    assert owner.contract_sha256 == __import__("hashlib").sha256(encoded).hexdigest()
    assert owner.contract_text.encode() == encoded


def test_factory_run_rejects_a_legacy_source_only_snapshot(
    cli_runner,
    tmp_path,
    tmp_config_dir,
):
    from safeyolo.factory_contract import approve_snapshot, canonical_snapshot, snapshot_id

    _identifier, snapshot_path = approve_snapshot(load_factory_file(_factory_file(tmp_path)))
    payload = json.loads(snapshot_path.read_text())
    payload.pop("operator_input")
    legacy_identifier = snapshot_id(payload)
    legacy_path = snapshot_path.with_name(f"{legacy_identifier}.json")
    legacy_path.write_bytes(canonical_snapshot(payload))
    (snapshot_path.parents[1] / "approved").write_text(legacy_identifier + "\n")

    result = cli_runner.invoke(app, ["factory", "run", "backlog"])

    assert result.exit_code == 1
    assert "snapshot has no operator_input" in result.output
    assert "cannot be" in result.output
    assert (
        "cannot be run; check and approve a reachable contract"
        in " ".join(result.output.split())
    )
