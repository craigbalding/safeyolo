"""Acceptance tests for the read-only supervised factory doctor."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from safeyolo.agents_store import load_agent, save_agent
from safeyolo.cli import app
from safeyolo.coord import api as coord_api
from safeyolo.coord import store as coord_store
from safeyolo.factory_contract import approve_snapshot, load_approved_snapshot, load_factory_file
from safeyolo.factory_doctor import (
    _BACKLOG_COORDINATOR_CONTRACT_SHA256,
    _PROCESS_EXECUTABLE_MARKER,
    _PROCESS_EXPECTED_MARKER,
    _PROCESS_STAT_MARKER,
    _expected_supervised_command,
    _expected_supervisor_config,
    _inspect_brief,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _factory_file(
    tmp_path: Path,
    *,
    coordinator_contract: str | None = None,
    room: str = "backlog",
) -> Path:
    if coordinator_contract is None:
        coordinator_contract = (
            REPO_ROOT / "docs/factories/backlog-coordinator.md"
        ).read_text()
    (tmp_path / "coordinator.md").write_text(coordinator_contract)
    for name in ("owner", "reviewer"):
        (tmp_path / f"{name}.md").write_text(f"# {name.title()}\n")
    path = tmp_path / "backlog.toml"
    path.write_text(
        'schema = "safeyolo.factory/v1"\n'
        'name = "backlog"\n'
        f'room = "{room}"\n\n'
        "[operator_input]\n"
        'to = "coordinator"\n'
        'types = ["NEXT"]\n\n'
        '[roles.coordinator]\nagent = "relay"\ncontract = "coordinator.md"\n\n'
        '[roles.owner]\nagent = "forge"\ncontract = "owner.md"\n\n'
        '[roles.reviewer]\nagent = "lens"\ncontract = "reviewer.md"\n\n'
        '[[handoffs]]\nrequest = "TASK"\nfrom = "coordinator"\nto = "owner"\n'
        'responses = ["DONE", "BLOCKED", "FAILED"]\n\n'
        '[[handoffs]]\nrequest = "REVIEW_READY"\nfrom = "owner"\nto = "reviewer"\n'
        'responses = ["READY", "CHANGES_REQUIRED", "BLOCKED"]\n'
    )
    return path


class _Process:
    def __init__(self, output: str, returncode: int = 0):
        self.output = output
        self.returncode = returncode

    def communicate(self, timeout=None):
        return self.output, ""

    def kill(self):
        self.returncode = -9


def _process_identity_sections(
    executables: dict[int, str],
    *,
    codex_command: str = "/home/agent/.local/bin/codex",
    codex_executable: str = "/home/agent/.local/lib/codex.js",
    node_executable: str = "/opt/node/bin/node",
) -> str:
    executable_lines = "\n".join(f"{pid}\t{path}" for pid, path in executables.items())
    return (
        f"\n{_PROCESS_EXECUTABLE_MARKER}\n{executable_lines}\n"
        f"{_PROCESS_EXPECTED_MARKER}\n"
        "python3=/usr/bin/python3.13\n"
        "mcp-python=/usr/bin/python3.13\n"
        f"codex-command={codex_command}\n"
        f"codex-executable={codex_executable}\n"
        f"node-executable={node_executable}\n"
    )


def _healthy_process_output(index: int, *, include_mcp: bool = True, native_codex: bool = False) -> str:
    supervisor = 50 + index
    codex = 100 + index
    mcp = 200 + index
    codex_command = "/opt/codex/bin/codex" if native_codex else "/home/agent/.local/bin/codex"
    codex_executable = codex_command if native_codex else "/home/agent/.local/lib/codex.js"
    lines = [
        f"{supervisor} 1 {supervisor} python3 /home/agent/.safeyolo/codex-coord-supervisor.py -- --flag",
        (
            f"{codex} {supervisor} {codex} {codex_command} exec resume thread"
            if native_codex
            else f"{codex} {supervisor} {codex} node {codex_command} exec resume thread"
        ),
    ]
    executables = {
        supervisor: "/usr/bin/python3.13",
        codex: codex_command if native_codex else "/opt/node/bin/node",
    }
    if include_mcp:
        lines.append(
            f"{mcp} {codex} {codex} /home/agent/.safeyolo/venv/bin/python /home/agent/.safeyolo/safeyolo-coord-mcp.py"
        )
        executables[mcp] = "/usr/bin/python3.13"
    stat_fields = ["S", str(supervisor), str(codex), *("0" for _ in range(16)), "1234", "0"]
    return (
        "\n".join(lines)
        + _process_identity_sections(
            executables,
            codex_command=codex_command,
            codex_executable=codex_executable,
        )
        + f"\n{_PROCESS_STAT_MARKER}\n{codex} (codex) "
        + " ".join(stat_fields)
    )


@pytest.fixture
def factory_runtime(tmp_path, tmp_config_dir, monkeypatch):
    approve_snapshot(load_factory_file(_factory_file(tmp_path)))
    _identifier, snapshot_path, payload = load_approved_snapshot("backlog")
    host_script = REPO_ROOT / "contrib/codex-coord-host-setup.sh"
    running = {"relay": True, "forge": True, "lens": True}
    process_output: dict[str, str] = {}
    rootfs: dict[str, Path] = {}
    homes: dict[str, Path] = {}

    for index, (role_name, role) in enumerate(payload["roles"].items(), start=1):
        name = role["agent"]
        workspace = tmp_path / f"{name}-workspace"
        workspace.mkdir()
        save_agent(
            name,
            {
                "agent_id": f"ag-{index:032x}",
                "folder": str(workspace),
                "host_script": str(host_script),
            },
        )
        agent_dir = tmp_config_dir / "agents" / name
        home = agent_dir / "home"
        staged = home / ".safeyolo"
        codex = home / ".codex"
        staged.mkdir(parents=True)
        codex.mkdir()
        homes[name] = home
        rootfs[name] = tmp_path / f"{name}-rootfs"
        rootfs[name].mkdir()

        command = home / ".safeyolo-command"
        command.write_text(_expected_supervised_command())
        command.chmod(0o755)
        for filename, source_name in (
            ("codex-coord-supervisor.py", "codex-coord-supervisor.py"),
            ("safeyolo-coord-mcp.py", "safeyolo-coord-mcp.py"),
            ("safeyolo-coord-mcp-launcher", "safeyolo-coord-mcp-launcher.sh"),
        ):
            artifact = staged / filename
            artifact.write_bytes((REPO_ROOT / "contrib" / source_name).read_bytes())
            artifact.chmod(0o755)
        process_output[name] = _healthy_process_output(index)
        (staged / "codex-coord-supervisor.json").write_text(
            json.dumps(_expected_supervisor_config(name, role_name, payload)) + "\n"
        )
        baseline = (REPO_ROOT / "docs/AGENTS.md").read_text()
        (staged / "AGENTS.md").write_text(baseline.rstrip() + "\n\n---\n\n" + role["contract_text"].lstrip())
        (staged / "codex-coord-supervisor-state.json").write_text(
            json.dumps(
                {
                    "version": 6,
                    "thread_id": "thread-1",
                    "safe_cursor": 7,
                    "recent_attention_ids": [],
                    "in_flight": [],
                    "awaiting_handoffs": [],
                    "briefs": {},
                    "consecutive_failures": 0,
                    "owned_process": {
                        "pid": 100 + index,
                        "start_time": "1234",
                        "descendants": [],
                    },
                }
            )
            + "\n"
        )
        (codex / "config.toml").write_text(
            "[mcp_servers.safeyolo-coord]\n"
            'command = "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"\n'
            "args = []\n"
            "tool_timeout_sec = 330\n"
        )

    platform = SimpleNamespace(
        agent_rootfs_path=lambda name: rootfs[name],
        is_sandbox_running=lambda name: running[name],
        popen_in_sandbox=lambda name, command, user: _Process(process_output[name]),
    )

    class HealthyAdminAPI:
        def __init__(self, **_kwargs):
            pass

        def health(self):
            return {"status": "ok"}

    monkeypatch.setattr("safeyolo.factory_doctor.get_platform", lambda: platform)
    monkeypatch.setattr("safeyolo.factory_doctor.AdminAPI", HealthyAdminAPI)
    monkeypatch.setattr(
        "safeyolo.factory_doctor.coord_nats.status",
        lambda: {"healthy": True, "state": "healthy"},
    )
    monkeypatch.setattr(
        "safeyolo.factory_doctor.coord_api.inspect_room_access",
        lambda _room, principals: {
            "room_id": "rm-test",
            "room_name": "backlog",
            "permissions": {f"{kind}:{principal_id}": ["send", "receive"] for kind, principal_id in principals},
        },
    )
    monkeypatch.setattr(
        "safeyolo.factory_doctor.coord_api.show_brief",
        lambda _room: {"revision": 0, "content_hash": None, "markdown": None},
    )
    return {
        "homes": homes,
        "running": running,
        "process_output": process_output,
        "snapshot_path": snapshot_path,
    }


def test_factory_doctor_reports_a_healthy_running_factory(cli_runner, factory_runtime):
    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=snapshot" in result.output
    assert "PASS component=coord-nats managed NATS is healthy" in result.output
    assert result.output.count("PASS component=agent-room ") == 3
    assert result.output.count("PASS component=agent-room-grant ") == 6
    assert "PASS component=staging role=owner agent=forge" in result.output
    assert "PASS component=processes role=reviewer agent=lens" in result.output
    assert "PASS component=coord-brief room=backlog state=none" in result.output
    assert "role-contract-intake=valid" in result.output
    assert "safeyolo coord brief show backlog" in result.output
    assert "--expected-revision 0" in result.output
    assert "SUMMARY factory=backlog status=PASS" in result.output
    assert "contract_text" not in result.output
    assert "recent_attention_ids" not in result.output


def test_shipped_backlog_contract_hash_is_pinned():
    contract = REPO_ROOT / "docs/factories/backlog-coordinator.md"

    assert hashlib.sha256(contract.read_bytes()).hexdigest() == (
        _BACKLOG_COORDINATOR_CONTRACT_SHA256
    )


def test_factory_doctor_does_not_invent_next_mode_for_custom_factory(monkeypatch):
    monkeypatch.setattr(
        "safeyolo.factory_doctor.coord_api.show_brief",
        lambda _room: {"revision": 0, "content_hash": None, "markdown": None},
    )
    checks = []

    _inspect_brief(
        checks,
        {
            "name": "custom",
            "room": "custom",
            "operator_input": {"to": "coordinator", "types": ["START"]},
        },
    )

    assert len(checks) == 1
    assert checks[0].status == "PASS"
    assert checks[0].detail.startswith("room=custom state=none ")
    assert "role-contract-intake" not in checks[0].detail
    assert "safeyolo coord brief show custom" in checks[0].detail
    assert "--expected-revision 0" in checks[0].detail


def test_factory_doctor_does_not_invent_next_mode_for_custom_backlog_contract(
    tmp_path, monkeypatch
):
    custom_contract = "# Custom coordinator\n\nNEXT records a note and never selects work.\n"
    payload = load_factory_file(
        _factory_file(
            tmp_path,
            coordinator_contract=custom_contract,
            room="custom-room",
        )
    ).snapshot_payload()
    monkeypatch.setattr(
        "safeyolo.factory_doctor.coord_api.show_brief",
        lambda _room: {"revision": 0, "content_hash": None, "markdown": None},
    )
    checks = []

    _inspect_brief(checks, payload)

    assert payload["name"] == "backlog"
    assert payload["operator_input"]["types"] == ["NEXT"]
    assert payload["roles"]["coordinator"]["contract_sha256"] != (
        _BACKLOG_COORDINATOR_CONTRACT_SHA256
    )
    assert len(checks) == 1
    assert checks[0].status == "PASS"
    assert checks[0].detail.startswith("room=custom-room state=none ")
    assert "role-contract-intake" not in checks[0].detail


def test_factory_doctor_reports_present_brief_metadata_without_body(
    cli_runner, factory_runtime, monkeypatch
):
    markdown = "# Private operator meaning\n\nDo not print this body.\n"
    content_hash = hashlib.sha256(markdown.encode()).hexdigest()
    monkeypatch.setattr(
        "safeyolo.factory_doctor.coord_api.show_brief",
        lambda _room: {
            "revision": 7,
            "content_hash": content_hash,
            "markdown": markdown,
        },
    )

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])
    output = " ".join(result.output.split())

    assert result.exit_code == 0, result.output
    assert (
        f"PASS component=coord-brief room=backlog revision=7 "
        f"content_hash={content_hash}"
        in output
    )
    assert "body=not-inspected" in output
    assert "meaning=operator-owned" in output
    assert "--expected-revision 7" in output
    assert "Private operator meaning" not in result.output
    assert "Do not print this body" not in result.output


def test_factory_doctor_reports_missing_agent_room_grant(
    cli_runner,
    factory_runtime,
    monkeypatch,
):
    def inspect(room, principals):
        permissions = {
            f"{kind}:{principal_id}": ["send", "receive"]
            for kind, principal_id in principals
        }
        if room == "lens-agent":
            lens = next(key for key in permissions if key.startswith("agent:"))
            permissions[lens] = ["receive"]
        return {"room_id": f"room-{room}", "room_name": room, "permissions": permissions}

    monkeypatch.setattr("safeyolo.factory_doctor.coord_api.inspect_room_access", inspect)

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=agent-room-grant role=reviewer agent=lens" in result.output
    assert "room=lens-agent missing=send" in result.output


def test_factory_doctor_rejects_a_live_unrelated_proxy_pid(cli_runner, factory_runtime, tmp_config_dir, monkeypatch):
    class UnavailableAdminAPI:
        def __init__(self, **_kwargs):
            pass

        def health(self):
            raise OSError("not the proxy")

    proxy_pid = tmp_config_dir / "data/proxy.pid"
    proxy_pid.parent.mkdir(exist_ok=True)
    proxy_pid.write_text(str(os.getpid()))
    monkeypatch.setattr("safeyolo.factory_doctor.AdminAPI", UnavailableAdminAPI)

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=proxy traffic proxy is not running" in result.output


def test_factory_doctor_accepts_a_native_codex_executable(cli_runner, factory_runtime):
    factory_runtime["process_output"]["forge"] = _healthy_process_output(2, native_codex=True)

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=processes role=owner agent=forge" in result.output


def test_factory_doctor_accepts_a_healthy_between_turn_checkpoint(cli_runner, factory_runtime):
    state_path = factory_runtime["homes"]["forge"] / ".safeyolo/codex-coord-supervisor-state.json"
    state = json.loads(state_path.read_text())
    state["owned_process"] = None
    state_path.write_text(json.dumps(state) + "\n")

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert "PASS component=processes role=owner agent=forge bounded supervisor is between Codex turns" in output
    assert "checkpoint has no active Codex process identity" not in result.output


def test_factory_doctor_treats_a_checkpoint_pid_transition_as_healthy(cli_runner, factory_runtime):
    # The checkpointed Codex can exit between `ps` and the /proc stat read. The
    # supervisor remains present, so this is a normal bounded-turn transition,
    # not a reason to stop in-flight work.
    supervisor = 52
    factory_runtime["process_output"]["forge"] = (
        f"{supervisor} 1 {supervisor} python3 /home/agent/.safeyolo/codex-coord-supervisor.py --\n"
        + _process_identity_sections({supervisor: "/usr/bin/python3.13"})
        + f"\n{_PROCESS_STAT_MARKER}\n"
    )

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert "bounded supervisor transition observed during inspection" in output
    assert "stop and rerun" not in output


def test_factory_doctor_accepts_the_mise_npm_codex_shim_tree(cli_runner, factory_runtime):
    supervisor, codex, mcp = 52, 102, 202
    command = (
        f"{supervisor} 1 {supervisor} python3 /home/agent/.safeyolo/codex-coord-supervisor.py --\n"
        f"{codex} {supervisor} {codex} node /home/agent/.mise/installs/npm-openai-codex/0.152.0/node_modules/@openai/codex/bin/codex.js exec resume thread\n"
        f"{mcp} {codex} {codex} /home/agent/.safeyolo/venv/bin/python /home/agent/.safeyolo/safeyolo-coord-mcp.py\n"
    )
    executables = {
        supervisor: "/usr/bin/python3.13",
        codex: "/home/agent/.mise/installs/node/22.23.2/bin/node",
        mcp: "/usr/bin/python3.13",
    }
    factory_runtime["process_output"]["forge"] = (
        command
        + _process_identity_sections(
            executables,
            codex_command="/home/agent/.mise/shims/codex",
            codex_executable="/usr/local/bin/mise",
            node_executable="/usr/local/bin/mise",
        )
        + f"\n{_PROCESS_STAT_MARKER}\n"
        + f"{codex} (codex) "
        + " ".join(["S", str(supervisor), str(codex), *(["0"] * 16), "1234", "0"])
    )

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=processes role=owner agent=forge" in result.output


def test_factory_doctor_accepts_native_codex_execed_by_mise_npm_launcher(
    cli_runner,
    factory_runtime,
):
    supervisor, codex, mcp = 52, 102, 202
    native = (
        "/home/agent/.mise/installs/npm-openai-codex/0.152.0/node_modules/.mise/"
        "@openai+codex-linux-arm64@0.152.0-linux-arm64/node_modules/"
        "@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"
    )
    command = (
        f"{supervisor} 1 {supervisor} python3 /home/agent/.safeyolo/codex-coord-supervisor.py --\n"
        f"{codex} {supervisor} {codex} {native} exec resume --json thread\n"
        f"{mcp} {codex} {codex} /home/agent/.safeyolo/venv/bin/python "
        "/home/agent/.safeyolo/safeyolo-coord-mcp.py\n"
    )
    factory_runtime["process_output"]["forge"] = (
        command
        + _process_identity_sections(
            {
                supervisor: "/usr/bin/python3.13",
                codex: native,
                mcp: "/usr/bin/python3.13",
            },
            codex_command="/home/agent/.mise/shims/codex",
            codex_executable="/usr/local/bin/mise",
            node_executable="/home/agent/.mise/installs/node/22.23.2/bin/node",
        )
        + f"\n{_PROCESS_STAT_MARKER}\n"
        + f"{codex} (codex) "
        + " ".join(["S", str(supervisor), str(codex), *(["0"] * 16), "1234", "0"])
    )

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=processes role=owner agent=forge" in result.output


def test_factory_doctor_treats_stopped_roles_as_state_not_corruption(cli_runner, factory_runtime):
    factory_runtime["running"].update({"relay": False, "forge": False, "lens": False})

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert result.output.count("WARN component=sandbox-runtime") == 3
    assert "state=stopped" in result.output
    assert "SUMMARY factory=backlog status=WARN" in result.output
    assert "checkpoint is invalid" not in result.output


@pytest.mark.parametrize("version", [1, 2, 3, 4])
def test_factory_doctor_accepts_supervisor_compatible_legacy_checkpoints(cli_runner, factory_runtime, version):
    state_path = factory_runtime["homes"]["forge"] / ".safeyolo/codex-coord-supervisor-state.json"
    state = json.loads(state_path.read_text())
    state["version"] = version
    state["awaiting_handoff"] = None
    state.pop("awaiting_handoffs")
    if version == 1:
        state.pop("awaiting_handoff")
    if version < 4:
        state.pop("briefs")
    state_path.write_text(json.dumps(state) + "\n")
    before = state_path.read_bytes()

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=checkpoint role=owner agent=forge" in result.output
    assert state_path.read_bytes() == before


def test_factory_doctor_accepts_version_five_checkpoint_without_mutating_it(
    cli_runner,
    factory_runtime,
):
    state_path = factory_runtime["homes"]["forge"] / ".safeyolo/codex-coord-supervisor-state.json"
    state = json.loads(state_path.read_text())
    state["version"] = 5
    state["thread_id"] = "legacy-wait-thread"
    state_path.write_text(json.dumps(state) + "\n")
    before = state_path.read_bytes()

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=checkpoint role=owner agent=forge" in result.output
    assert state_path.read_bytes() == before


def test_factory_doctor_accepts_current_concurrent_awaiting_handoffs(cli_runner, factory_runtime):
    state_path = factory_runtime["homes"]["relay"] / ".safeyolo/codex-coord-supervisor-state.json"
    state = json.loads(state_path.read_text())
    state["awaiting_handoffs"] = [
        {
            "room_name": "backlog",
            "request": "REVIEW_READY",
            "recipient_agent": reviewer,
            "body": (
                "REVIEW_READY "
                f"target=https://github.com/craigbalding/safeyolo/pull/{pr}/commits/{head}"
            ),
            "correlation": {
                "target": (
                    f"https://github.com/craigbalding/safeyolo/pull/{pr}/commits/{head}"
                )
            },
        }
        for reviewer, pr, head in (
            ("lens", 518, "a" * 40),
            ("audit", 519, "b" * 40),
        )
    ]
    state_path.write_text(json.dumps(state) + "\n")

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 0, result.output
    assert "PASS component=checkpoint role=coordinator agent=relay" in result.output


def test_factory_doctor_rejects_null_current_awaiting_handoff(cli_runner, factory_runtime):
    state_path = factory_runtime["homes"]["forge"] / ".safeyolo/codex-coord-supervisor-state.json"
    state = json.loads(state_path.read_text())
    state["awaiting_handoffs"] = [None]
    state_path.write_text(json.dumps(state) + "\n")
    before = state_path.read_bytes()

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=checkpoint role=owner agent=forge checkpoint is invalid" in result.output
    assert state_path.read_bytes() == before


def test_factory_doctor_rejects_old_in_flight_task_protocol(cli_runner, factory_runtime):
    state_path = factory_runtime["homes"]["forge"] / ".safeyolo/codex-coord-supervisor-state.json"
    state = json.loads(state_path.read_text())
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
    state_path.write_text(json.dumps(state) + "\n")

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=checkpoint role=owner agent=forge checkpoint is invalid" in result.output


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("folder", "FAIL component=workspace role=owner agent=forge configured workspace path is invalid"),
        (
            "host_script",
            "FAIL component=host-script role=owner agent=forge configured host-script path is invalid",
        ),
    ],
)
def test_factory_doctor_reports_invalid_configured_paths(cli_runner, factory_runtime, field, expected):
    metadata = load_agent("forge")
    metadata[field] = "invalid\x00path"
    save_agent("forge", metadata)

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert expected in " ".join(result.output.split())


@pytest.mark.parametrize(
    ("break_runtime", "expected"),
    [
        ("nats", "FAIL component=coord-nats managed NATS state=not-running"),
        ("staging", "FAIL component=staging role=owner agent=forge"),
        ("process", "FAIL component=processes role=owner agent=forge missing running=coord-mcp"),
    ],
)
def test_factory_doctor_names_independently_broken_components(
    cli_runner, factory_runtime, monkeypatch, break_runtime, expected
):
    if break_runtime == "nats":
        monkeypatch.setattr(
            "safeyolo.factory_doctor.coord_nats.status",
            lambda: {"healthy": False, "state": "not-running"},
        )
    elif break_runtime == "staging":
        (factory_runtime["homes"]["forge"] / ".safeyolo-command").unlink()
    else:
        factory_runtime["process_output"]["forge"] = _healthy_process_output(2, include_mcp=False)

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert expected in result.output
    assert "recovery=" in result.output
    assert "SUMMARY factory=backlog status=FAIL" in result.output


def test_factory_doctor_rejects_process_marker_substrings_without_owned_relationships(cli_runner, factory_runtime):
    stat_fields = ["S", "1", "102", *("0" for _ in range(16)), "1234", "0"]
    factory_runtime["process_output"]["forge"] = (
        "102 1 102 arbitrary codex-coord-supervisor.py codex exec safeyolo-coord-mcp.py\n"
        + _process_identity_sections({102: "/tmp/arbitrary"})
        + f"\n{_PROCESS_STAT_MARKER}\n"
        "102 (arbitrary) " + " ".join(stat_fields)
    )

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    output = " ".join(result.output.split())
    assert "FAIL component=processes role=owner agent=forge" in output
    assert "supervisor,coord-mcp" in output


@pytest.mark.parametrize(
    ("codex_command", "codex_executable"),
    [
        ("/tmp/codex exec resume thread", "/tmp/codex"),
        ("/tmp/node /tmp/codex exec resume thread", "/tmp/node"),
    ],
)
def test_factory_doctor_rejects_arbitrary_executables_with_valid_process_relationships(
    cli_runner, factory_runtime, codex_command, codex_executable
):
    stat_fields = ["S", "52", "102", *("0" for _ in range(16)), "1234", "0"]
    factory_runtime["process_output"]["forge"] = (
        "52 1 52 /tmp/python3 /home/agent/.safeyolo/codex-coord-supervisor.py --\n"
        + f"102 52 102 {codex_command}\n"
        + "202 102 102 /tmp/python /home/agent/.safeyolo/safeyolo-coord-mcp.py\n"
        + _process_identity_sections({52: "/tmp/python3", 102: codex_executable, 202: "/tmp/python"})
        + f"\n{_PROCESS_STAT_MARKER}\n"
        "102 (arbitrary) " + " ".join(stat_fields)
    )

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    output = " ".join(result.output.split())
    assert "FAIL component=processes role=owner agent=forge" in output
    assert "missing running=codex,supervisor,coord-mcp" in output


def test_factory_doctor_rejects_noop_staged_command_and_artifacts(cli_runner, factory_runtime):
    home = factory_runtime["homes"]["forge"]
    (home / ".safeyolo-command").write_text(
        '#!/bin/sh\n# exec python3 "$HOME/.safeyolo/codex-coord-supervisor.py"\nexit 0\n'
    )
    for filename in (
        "codex-coord-supervisor.py",
        "safeyolo-coord-mcp.py",
        "safeyolo-coord-mcp-launcher",
    ):
        (home / ".safeyolo" / filename).write_text("#!/bin/sh\nexit 0\n")

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=staging role=owner agent=forge" in result.output
    assert "staged command does not match" in result.output


@pytest.mark.parametrize(
    "filename",
    ["codex-coord-supervisor.py", "safeyolo-coord-mcp.py", "safeyolo-coord-mcp-launcher"],
)
def test_factory_doctor_rejects_noop_staged_artifact(cli_runner, factory_runtime, filename):
    artifact = factory_runtime["homes"]["forge"] / ".safeyolo" / filename
    artifact.write_text("#!/bin/sh\nexit 0\n")

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    output = " ".join(result.output.split())
    assert "FAIL component=staging role=owner agent=forge" in output
    assert "staged artifact does not match" in output
    assert filename in output


def test_factory_doctor_rejects_prepended_staged_instructions(cli_runner, factory_runtime):
    instructions = factory_runtime["homes"]["forge"] / ".safeyolo/AGENTS.md"
    instructions.write_text("# Arbitrary developer instructions\n\n" + instructions.read_text())

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    output = " ".join(result.output.split())
    assert "FAIL component=staging role=owner agent=forge" in output
    assert "staged role contract does not match" in output


def test_factory_doctor_fails_on_corrupt_state_without_changing_it(cli_runner, factory_runtime):
    state = factory_runtime["homes"]["forge"] / ".safeyolo/codex-coord-supervisor-state.json"
    state.write_text('{"version":4,"safe_cursor":"secret payload"}\n')
    before = state.read_bytes()
    before_stat = state.stat()

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=checkpoint role=owner agent=forge checkpoint is invalid" in result.output
    assert "secret payload" not in result.output
    assert state.read_bytes() == before
    assert state.stat().st_mtime_ns == before_stat.st_mtime_ns


def test_factory_doctor_rejects_a_tampered_approved_snapshot(cli_runner, factory_runtime):
    snapshot = factory_runtime["snapshot_path"]
    original = snapshot.read_bytes()
    tampered = original.replace(b"# Owner", b"# Tampered owner")
    snapshot.write_bytes(tampered)

    result = cli_runner.invoke(app, ["factory", "doctor", "backlog"])

    assert result.exit_code == 1
    assert "FAIL component=snapshot approved snapshot is invalid" in result.output
    assert "SUMMARY factory=backlog status=FAIL" in result.output
    assert snapshot.read_bytes() == tampered


def test_read_only_coord_inspection_does_not_create_missing_state(tmp_path, monkeypatch):
    coord_dir = tmp_path / "missing-coord"
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(coord_dir))

    with pytest.raises(FileNotFoundError):
        coord_api.inspect_room_access("backlog", [("operator", "operator")])

    assert not coord_dir.exists()


def test_read_only_coord_inspection_reports_existing_grants(tmp_path, monkeypatch):
    coord_dir = tmp_path / "coord"
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(coord_dir))
    coord_store.init_schema()
    with coord_store.connect() as conn:
        conn.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES (?, ?, ?)",
            ("rm-test", "backlog", 1),
        )
        conn.execute(
            """INSERT INTO memberships(
                   room_id, principal_kind, principal_id, permissions,
                   history_visibility, granted_at, revoked_at
               ) VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            ("rm-test", "operator", "operator", "receive,send", "retained", 1),
        )

    def directory_state() -> dict[str, tuple[int, int, int, int, int, int, int]]:
        return {
            entry.name: (
                metadata.st_mode,
                metadata.st_ino,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            for entry in coord_dir.iterdir()
            if (metadata := entry.stat())
        }

    before = directory_state()
    before_directory_metadata = (
        coord_dir.stat().st_mode,
        coord_dir.stat().st_mtime_ns,
        coord_dir.stat().st_ctime_ns,
    )
    assert set(before) == {"v0.db"}

    result = coord_api.inspect_room_access(
        "backlog",
        [("operator", "operator"), ("agent", "ag-" + "1" * 32)],
    )

    assert result == {
        "room_id": "rm-test",
        "room_name": "backlog",
        "permissions": {
            "operator:operator": ["receive", "send"],
            "agent:ag-" + "1" * 32: [],
        },
    }
    assert directory_state() == before
    assert (
        coord_dir.stat().st_mode,
        coord_dir.stat().st_mtime_ns,
        coord_dir.stat().st_ctime_ns,
    ) == before_directory_metadata
    with coord_store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM rooms").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM memberships").fetchone()[0] == 1


def test_read_only_coord_inspection_observes_uncheckpointed_wal(tmp_path, monkeypatch):
    coord_dir = tmp_path / "coord"
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(coord_dir))
    coord_store.init_schema()
    with coord_store.connect() as writer:
        writer.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES (?, ?, ?)",
            ("rm-backlog", "backlog", 1),
        )
        writer.execute(
            """INSERT INTO memberships(
                   room_id, principal_kind, principal_id, permissions,
                   history_visibility, granted_at, revoked_at
               ) VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            ("rm-backlog", "operator", "operator", "receive,send", "retained", 1),
        )
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "UPDATE memberships SET revoked_at = ? WHERE room_id = ?",
            (2, "rm-backlog"),
        )
        writer.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES (?, ?, ?)",
            ("rm-live", "live", 2),
        )

        wal_path = Path(f"{coord_store.db_path()}-wal")
        assert wal_path.stat().st_size > 0

        database_path = coord_store.db_path()
        before_entries = {entry.name for entry in coord_dir.iterdir()}
        before_database = database_path.read_bytes()
        before_wal = wal_path.read_bytes()
        before_metadata = {
            entry.name: (
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            for entry in coord_dir.iterdir()
            if (metadata := entry.stat())
        }
        assert coord_api.inspect_room_access(
            "backlog", [("operator", "operator")]
        ) == {
            "room_id": "rm-backlog",
            "room_name": "backlog",
            "permissions": {"operator:operator": []},
        }
        assert coord_api.inspect_room_access("live", []) == {
            "room_id": "rm-live",
            "room_name": "live",
            "permissions": {},
        }
        assert {entry.name for entry in coord_dir.iterdir()} == before_entries
        assert database_path.read_bytes() == before_database
        assert wal_path.read_bytes() == before_wal
        assert {
            entry.name: (
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
            for entry in coord_dir.iterdir()
            if (metadata := entry.stat())
        } == before_metadata


def test_read_only_coord_inspection_fails_when_wal_has_no_shared_memory(
    tmp_path, monkeypatch
):
    coord_dir = tmp_path / "coord"
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(coord_dir))
    coord_store.init_schema()
    with coord_store.connect() as writer:
        writer.execute(
            "INSERT INTO rooms(room_id, name, created_at) VALUES (?, ?, ?)",
            ("rm-backlog", "backlog", 1),
        )
        writer.execute(
            """INSERT INTO memberships(
                   room_id, principal_kind, principal_id, permissions,
                   history_visibility, granted_at, revoked_at
               ) VALUES (?, ?, ?, ?, ?, ?, NULL)""",
            ("rm-backlog", "operator", "operator", "receive,send", "retained", 1),
        )
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute(
            "UPDATE memberships SET revoked_at = ? WHERE room_id = ?",
            (2, "rm-backlog"),
        )

        database_path = coord_store.db_path()
        wal_path = Path(f"{database_path}-wal")
        shm_path = Path(f"{database_path}-shm")
        assert wal_path.stat().st_size > 0
        shm_path.unlink()
        before_entries = {entry.name for entry in coord_dir.iterdir()}
        before_database = database_path.read_bytes()
        before_wal = wal_path.read_bytes()

        with pytest.raises(
            coord_store.SchemaError,
            match="coord WAL exists without its shared-memory index",
        ):
            coord_api.inspect_room_access("backlog", [("operator", "operator")])

        assert {entry.name for entry in coord_dir.iterdir()} == before_entries
        assert database_path.read_bytes() == before_database
        assert wal_path.read_bytes() == before_wal
        assert not shm_path.exists()
