"""Installed Factory entry and staged consumers, without a guest or model launch.

The optional launch test needs an explicitly prepared disposable Ubuntu host.
It is separate from these source fixtures and the paid W4 work witness.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.proxy_contracts.test_gateway_provider import _provider_run
from tests.proxy_contracts.test_native_coord_operator import POLICY as COORD_POLICY
from tests.proxy_contracts.test_native_coord_operator import terminal
from tests.proxy_contracts.test_native_policy_cli import native_instance


def contract(directory, *, mixed=True, claude=False):
    directory.mkdir()
    (directory / "role.md").write_text("Follow the assigned role and use canonical Coord handoffs.\n")
    source = directory / "factory.toml"
    source.write_text('''schema = "safeyolo.factory/v1"
name = "fixture"
room = "fixture-work"
[operator_input]
to = "coordinator"
types = ["ACTIVATE", "RESUME"]
[roles.coordinator]
agent = "fixture-relay"
contract = "role.md"
args = ["--model", "selected-model"]
[roles.owner]
agent = "fixture-forge"
contract = "role.md"
''' + ('harness = "claude"\nargs = ["--model", "sonnet"]\n' if claude else '') + '''
[roles.reviewer]
agent = "fixture-lens"
contract = "role.md"
''' + ('harness = "pi"\nargs = ["--provider", "openai-codex", "--model", "selected-model"]\n' if mixed else '') + '''[[handoffs]]
request = "TASK"
from = "coordinator"
to = "owner"
responses = ["DONE", "BLOCKED", "FAILED"]
[[handoffs]]
request = "REVIEW_READY"
from = "owner"
to = "reviewer"
responses = ["READY", "CHANGES_REQUIRED", "BLOCKED"]
response_to = ["owner", "coordinator"]
[[updates]]
type = "CONTEXT"
from = "coordinator"
to = "owner"
fields = ["target"]
''')
    return source


def cli(instance, *arguments):
    result = instance.cli(*arguments)
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"
    return result


@contextmanager
def prepared(directory, nats_binary, *, source_fixture=False, claude=False):
    with native_instance(directory, source=None, agent_api=True, source_fixture=source_fixture) as instance:
        # Ordinary shell utilities are production prerequisites. No Python,
        # package import path or source-checkout helper is in the command PATH.
        tools = directory / "tools"
        tools.mkdir()
        for name in ("bash", "env", "cp", "chmod", "mkdir", "install", "stat", "id",
                     "dirname", "basename", "cat", "tail", "grep", "sed", "awk", "readlink",
                     "ln", "mv", "rm", "mktemp", "git", "openssl"):
            executable = shutil.which(name)
            assert executable is not None, name
            (tools / name).symlink_to(executable)
        instance.environment["PATH"] = os.pathsep.join((str(instance.root / "bin"), str(tools)))
        instance.environment["SAFEYOLO_NATS_TEST_INSTANCE"] = "1"
        for name in ("SAFEYOLO_COORD_EXECUTABLE", "SAFEYOLO_COORD_GUEST_BINARY",
                     "SAFEYOLO_FACTORY_SNAPSHOT", "SAFEYOLO_FACTORY_ROLE",
                     "SAFEYOLO_CODEX_COORD_SUPERVISOR", "SAFEYOLO_PI_COORD_SUPERVISOR",
                     "SAFEYOLO_CLAUDE_COORD_SUPERVISOR"):
            instance.environment.pop(name, None)
        source = contract(directory / "contract", claude=claude)
        cli(instance, "factory", "check", str(source))
        cli(instance, "factory", "approve", str(source), "--yes")
        cli(instance, "coord", "start", "--binary", str(nats_binary))
        workspaces = []
        for role in ("coordinator", "owner", "reviewer"):
            workspace = directory / f"repo-{role}"
            workspace.mkdir()
            workspaces.extend(("--workspace", f"{role}={workspace}"))
        try:
            result = cli(instance, "factory", "prepare", "fixture", *workspaces)
            assert "no models started" in result.stdout
            yield instance, workspaces
        finally:
            # No role runtime is launched by this fixture. Stop owned NATS
            # before removing only its copies of native staging artifacts.
            stopped = instance.cli("coord", "stop")
            assert stopped.returncode == 0, stopped.stderr
            for binary in instance.root.glob("agents/*/home/.safeyolo/safeyolo-coord"):
                binary.unlink(missing_ok=True)
            for binary in instance.root.glob("agents/*/config-share/safeyolo-guest"):
                binary.unlink(missing_ok=True)


def roles(instance):
    return tomllib.loads((instance.root / "policy.toml").read_text())["agents"]


def adopt_source_login(instance):
    """Synthetic local files let source tests reach setup, never a model call."""
    for name in ("fixture-relay", "fixture-forge"):
        home = instance.root / "agents" / name / "home"
        auth = home / ".codex/auth.json"
        auth.write_text('{"synthetic":"source-fixture-only"}')
        auth.chmod(0o600)
        result = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "codex-state",
                                 "--home", str(home), "adopt"], env=instance.environment,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr


def assert_no_role_launch(instance):
    for name in ("fixture-relay", "fixture-forge", "fixture-lens"):
        directory = instance.root / "agents" / name
        assert not list(directory.glob("runtime*"))
        assert not (directory / "home/.safeyolo/coord-supervisor-state.json").exists()


def test_setup_preview_keeps_exact_contract_and_approval_separate(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        source = tmp_path / "contract/factory.toml"
        pointer = instance.root / "factories/fixture/approved"
        approved = pointer.read_bytes()
        original = (source.parent / "role.md").read_text()
        (source.parent / "role.md").write_text("Changed unapproved role instructions.\n")
        preview = cli(instance, "factory", "setup", str(source), "--preview", "--yes")
        value = json.loads(preview.stdout)
        assert value["root"] == str(instance.root)
        assert value["source"] == str(source)
        assert value["approved"] is False
        assert value["previous_contract"]["roles"]["owner"]["contract_text"] == original
        assert value["selected_contract"]["roles"]["owner"]["contract_text"] == "Changed unapproved role instructions.\n"
        refused = instance.cli("factory", "setup", str(source))
        assert refused.returncode != 0
        assert '"status": "approval-required"' in refused.stdout
        assert str(source) in refused.stderr and "approve" in refused.stderr
        assert pointer.read_bytes() == approved
        assert_no_role_launch(instance)


@pytest.mark.parametrize("claude", [False, True])
def test_setup_resumes_prepared_roles_without_reapplying_or_initializing_checkpoints(tmp_path, _binary_cache, claude):
    with prepared(tmp_path, _binary_cache, claude=claude) as (instance, workspaces):
        source = tmp_path / "contract/factory.toml"
        before = roles(instance)
        entries = list(instance.root.glob("agents/*/home/.safeyolo-command"))
        staged = {path: (path.stat().st_ino, path.stat().st_mtime_ns) for path in entries}
        # Returning after preparation needs no repeated workspace selection or
        # approval. --yes alone never confirms missing checkpoints.
        for arguments in ((), ("--yes",), tuple(workspaces)):
            result = instance.cli("factory", "setup", str(source), *arguments)
            assert result.returncode != 0, result.stdout
            assert '"status": "checkpoint-required"' in result.stdout, result.stderr
            assert "--confirm-fresh-identity" in result.stderr
            assert "setup failed" not in result.stderr
            assert roles(instance) == before
            assert {path: (path.stat().st_ino, path.stat().st_mtime_ns) for path in entries} == staged
            assert_no_role_launch(instance)


@pytest.mark.parametrize("claude", [False, True])
def test_setup_keeps_valid_checkpoint_and_diagnoses_corrupt_checkpoint(tmp_path, _binary_cache, claude):
    with prepared(tmp_path, _binary_cache, claude=claude) as (instance, _):
        source = tmp_path / "contract/factory.toml"
        executable = instance.root / "bin/safeyolo-coord"
        if claude:
            coordinator = instance.root / "agents/fixture-relay/home/.safeyolo/coord-supervisor-state.json"
            initial = subprocess.check_output([str(executable), "read-state", str(coordinator)])
            subprocess.run([str(executable), "write-state", str(coordinator)], input=initial, check=True)
        agent = "fixture-forge" if claude else "fixture-relay"
        state = instance.root / f"agents/{agent}/home/.safeyolo/coord-supervisor-state.json"
        checkpoint = json.loads(subprocess.check_output([str(executable), "read-state", str(state)]))
        if claude:
            checkpoint["harness"] = "claude"
        checkpoint["safe_cursor"] = 91
        checkpoint["recent_attention_ids"] = ["attn-" + "c" * 32]
        subprocess.run([str(executable), "write-state", str(state)], input=json.dumps(checkpoint), text=True, check=True)
        before = state.read_bytes()
        result = instance.cli("factory", "setup", str(source))
        missing_role = "reviewer" if claude else "owner"
        assert result.returncode != 0 and f"role {missing_role}:" in result.stderr
        assert state.read_bytes() == before
        state.write_text("{broken checkpoint")
        result = instance.cli("factory", "setup", str(source), "--confirm-fresh-identity")
        corrupt_role = "owner" if claude else "coordinator"
        assert result.returncode != 0 and f"role {corrupt_role}:" in result.stderr
        assert "diagnostics" in result.stderr
        assert state.read_text() == "{broken checkpoint"
        missing_agent = "fixture-lens" if claude else "fixture-forge"
        assert not (state.parents[3] / f"{missing_agent}/home/.safeyolo/coord-supervisor-state.json").exists()


def test_setup_approval_and_workspace_requirements_do_not_launch_roles(tmp_path):
    with native_instance(tmp_path, source=None, agent_api=True) as instance:
        source = contract(tmp_path / "contract")
        value = json.loads(cli(instance, "factory", "setup", str(source), "--preview").stdout)
        assert value["previous_contract"] is None and value["approved"] is False
        assert all(role["runtime"]["runtime_state"] == "missing" for role in value["roles"])
        assert not (instance.root / "factories/fixture/approved").exists()
        assert instance.cli("factory", "setup", str(source)).returncode != 0
        assert not (instance.root / "factories/fixture/approved").exists()
        result = instance.cli("factory", "setup", str(source), "--yes")
        assert result.returncode != 0 and '"status": "workspace-required"' in result.stdout
        assert '"approved": true' in result.stdout
        assert "coordinator=PATH" in result.stderr
        assert not tomllib.loads((instance.root / "policy.toml").read_text()).get("agents", {})


def test_setup_keeps_explicit_codex_adoption_before_runtime_start(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        source = tmp_path / "contract/factory.toml"
        auth = instance.root / "agents/fixture-relay/home/.codex/auth.json"
        auth.write_text('{"synthetic":"unadopted-source-control"}')
        auth.chmod(0o600)
        original = auth.read_bytes()
        result = instance.cli("factory", "setup", str(source), "--confirm-fresh-identity")
        assert result.returncode != 0 and '"status": "authentication-required"' in result.stdout
        assert "explicit agent-local adopt or reset" in result.stderr
        assert auth.read_bytes() == original
        assert_no_role_launch(instance)


def test_setup_repairs_stopped_staging_and_explicitly_changed_workspace(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, workspaces):
        before = roles(instance)
        old = Path(before["fixture-forge"]["folder"])
        replacement = old.with_name("moved-owner-workspace")
        old.rename(replacement)
        choices = [f"owner={replacement}" if value.startswith("owner=") else value for value in workspaces]
        instructions = instance.root / "agents/fixture-forge/home/.safeyolo/AGENTS.md"
        original = instructions.read_bytes()
        instructions.write_text("Unapproved stopped staging.\n")
        result = instance.cli("factory", "setup", str(tmp_path / "contract/factory.toml"), *choices)
        assert result.returncode != 0 and '"status": "checkpoint-required"' in result.stdout, (result.stdout, result.stderr)
        current = roles(instance)
        assert current["fixture-forge"]["folder"] == str(replacement)
        assert {name: row["agent_id"] for name, row in current.items()} == {name: row["agent_id"] for name, row in before.items()}
        assert instructions.read_bytes() == original
        assert_no_role_launch(instance)


@pytest.mark.parametrize("claude", [False, True])
def test_installed_prepare_stages_codex_pi_and_retains_state_and_peer_grants(tmp_path, _binary_cache, claude):
    with prepared(tmp_path, _binary_cache, claude=claude) as (instance, workspaces):
        # The shared native bundle retains non-Factory inputs. Factory homes
        # stage native commands and link only their workflow skills.
        assert not list((instance.root / "agents").rglob("*.py"))
        skill = instance.root / "assets/skills/safeyolo"
        assert not (skill / "scripts/github_checks.py").exists()
        assert not (skill / "references/github-checks.md").exists()
        assert "GitHub composite checks" not in (skill / "SKILL.md").read_text()
        assert_no_role_launch(instance)
        bound = roles(instance)
        snapshot = (instance.root / "factories/fixture/approved").read_text().strip()
        for role, agent in (("coordinator", "fixture-relay"), ("owner", "fixture-forge"), ("reviewer", "fixture-lens")):
            home = instance.root / "agents" / agent / "home"
            config = json.loads((home / ".safeyolo/coord-supervisor.json").read_text())
            assert config["factory"]["snapshot_id"] == snapshot
            assert config["factory"]["role"] == role
            assert config["agent_name"] == agent
            assert config["factory"]["updates"][0]["fields"] == ["target"]
            payload = home / ".safeyolo-command.payload"
            if not payload.exists():
                payload = home / ".safeyolo-command"
            assert 'exec "$HOME/.safeyolo/safeyolo-coord" supervise "${supervisor_args[@]}" --' in payload.read_text()
            runtime = home / ".safeyolo/safeyolo-coord"
            with runtime.open("rb") as handle:
                assert hashlib.file_digest(handle, "sha256").hexdigest() == (instance.root / "assets/guest/safeyolo-coord.sha256").read_text().strip()
            if not claude or role != "owner":
                assert 'safeyolo-coord" repo-map "$@"' in (home / ".safeyolo/repo-map").read_text()
            assert not (home / ".agents/skills/safeyolo-lab-controller").is_symlink()
        pi = instance.root / "agents/fixture-lens/home"
        assert (pi / ".pi/agent/extensions/safeyolo-coord.ts").read_bytes() == (instance.root / "assets/contrib/pi-coord-extension.ts").read_bytes()
        assert (pi / ".pi/agent/skills/safeyolo").readlink() == Path("/safeyolo/skills/safeyolo")
        codex_home = instance.root / "agents/fixture-relay/home/.codex"
        if claude:
            claude_home = instance.root / "agents/fixture-forge/home"
            assert json.loads((claude_home / ".claude.json").read_text())["mcpServers"]["safeyolo-coord"]["command"] == "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"
            assert not (claude_home / ".claude/.credentials.json").exists()
            assert json.loads((claude_home / ".safeyolo/coord-supervisor.json").read_text())["harness"] == "claude"
        assert not (codex_home / "auth.json").exists()
        assert tomllib.loads((codex_home / "config.toml").read_text())["mcp_servers"]["safeyolo-coord"]["command"] == "/home/agent/.safeyolo/safeyolo-coord-mcp-launcher"
        codex = shutil.which("codex")
        assert codex is not None, "the retained Codex exec-policy consumer is required"
        policy = subprocess.run([codex, "execpolicy", "check", "--rules", str(codex_home / "rules/safeyolo-guest.rules"), "--", "bash", "-c", "rm -f /tmp/source-fixture-canary"], capture_output=True, text=True, timeout=10)
        assert policy.returncode == 0 and json.loads(policy.stdout)["decision"] == "allow", policy.stderr
        peer = tmp_path / "peer"
        peer.mkdir()
        cli(instance, "agent", "create", "observer", "--workspace", str(peer))
        cli(instance, "coord", "grant", "fixture-work", "observer", "receive")
        sent = json.loads(cli(instance, "factory", "send", "fixture", "Inspect the disposable fixture when assigned.").stdout)
        message = sent["envelope"]
        assert message["sender_kind"] == "operator" and message["sender_agent_id"] is None
        assert sent["attention_intent"]["mode"] == "targeted"
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            operator_grants = db.execute(
                "SELECT room_id, permissions, granted_at, revoked_at FROM memberships "
                "WHERE principal_kind='operator' ORDER BY room_id, granted_at",
            ).fetchall()
        # Approval alone retains the former staged binding and cannot report
        # readiness for changed role content.
        role_source = tmp_path / "contract/role.md"
        role_source.write_text(role_source.read_text() + "Updated approved instructions.\n")
        cli(instance, "factory", "approve", str(tmp_path / "contract/factory.toml"), "--yes")
        diagnosed = instance.cli("factory", "doctor", "fixture")
        assert diagnosed.returncode != 0
        old = next(item for item in json.loads(diagnosed.stdout)["checks"] if item.get("role") == "owner")
        assert old["staged_binding"]["snapshot"] == snapshot
        assert "differs from the approved" in old["error"]
        # Preparation continuity is distinct from the running W5 witness.
        cli(instance, "factory", "stop", "fixture")
        cli(instance, "factory", "prepare", "fixture", *workspaces)
        assert roles(instance) == {**bound, "observer": roles(instance)["observer"]}
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            assert db.execute(
                "SELECT room_id, permissions, granted_at, revoked_at FROM memberships "
                "WHERE principal_kind='operator' ORDER BY room_id, granted_at",
            ).fetchall() == operator_grants
        history = json.loads(cli(instance, "factory", "history", "fixture").stdout)
        assert [item["msg_id"] for item in history["messages"]] == [message["msg_id"]]
        assert history["messages"][0]["attention_intent"]["mode"] == "targeted"
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            permissions = db.execute("SELECT permissions FROM memberships WHERE principal_id=? AND revoked_at IS NULL ORDER BY granted_at DESC LIMIT 1", (roles(instance)["observer"]["agent_id"],)).fetchone()[0]
            assert permissions == "receive"
        assert_no_role_launch(instance)


def test_installed_repo_map_reads_working_tree_and_reports_guidance(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        repository = tmp_path / "repo-owner"
        source = repository / "fixture.py"
        source.write_text("def repair_fixture():\n    return 0\n")
        environment = instance.environment
        for arguments in (["init", "-q"], ["add", "fixture.py"], ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "fixture"]):
            subprocess.run(["git", "-C", str(repository), *arguments], env=environment, check=True, capture_output=True)
        source.write_text("def repair_fixture():\n    return 1\n")
        (repository / "binary").write_bytes(b"\0fixture")
        # APFS requires UTF-8 names; Linux also retains arbitrary pathname bytes.
        filename = "filename-é.rs" if os.uname().sysname == "Darwin" else os.fsdecode(b"filename-\xff.rs")
        (repository / filename).write_text("fn byte_filename() {}\n")
        before = source.read_bytes()
        result = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "repo-map", str(repository), "--query", "repair_fixture Factory", "--hints", str(instance.root / "assets/repo-map.toml")], env=environment, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert all(value in result.stdout for value in ("symbols=lexical", "repair_fixture", "GUIDANCE")), result.stdout
        # Task queries rank symbols and guidance. An exact symbol query renders
        # the current definition body, including edits after the Git commit.
        exact = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "repo-map", str(repository), "--query", "repair_fixture"], env=environment, capture_output=True, text=True, timeout=10)
        assert exact.returncode == 0, exact.stderr
        assert "DEFINITION fixture.py:1-2" in exact.stdout and "return 1" in exact.stdout, exact.stdout
        assert "return 0" not in exact.stdout
        mapped = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "repo-map", str(repository)], env=environment, capture_output=True, text=True, timeout=10)
        assert mapped.returncode == 0 and "binary" in mapped.stdout and "byte_filename" in mapped.stdout
        (repository / "pyproject.toml").write_text('[project]\nname="safeyolo"\n')
        staged = instance.root / "agents/fixture-forge/home/.safeyolo/safeyolo-coord"
        if os.uname().sysname == "Darwin":
            # The staged command is a Linux guest binary. Use the installed
            # Darwin consumer with the same adjacent guidance for this check.
            shutil.copyfile(staged.with_name("repo-map.toml"), instance.root / "bin/repo-map.toml")
            staged = instance.root / "bin/safeyolo-coord"
        fallback = subprocess.run([str(staged), "repo-map", str(repository), "--query", "Factory"], env=environment, capture_output=True, text=True, timeout=10)
        assert fallback.returncode == 0 and "GUIDANCE" in fallback.stdout
        assert source.read_bytes() == before


@pytest.mark.parametrize("claude", [False, True])
def test_installed_doctor_checks_actual_direct_and_wrapped_role_commands(tmp_path, _binary_cache, claude):
    with prepared(tmp_path, _binary_cache, claude=claude) as (instance, _):
        homes = {role: instance.root / f"agents/{agent}/home"
                 for role, agent in (("owner", "fixture-forge"), ("reviewer", "fixture-lens"))}
        originals = {role: (home / ".safeyolo-command").read_bytes() for role, home in homes.items()}

        def diagnosis(role, *, valid):
            result = instance.cli("factory", "doctor", "fixture")
            assert result.returncode != 0  # These source fixtures have no role runtime.
            check = next(item for item in json.loads(result.stdout)["checks"] if item.get("role") == role)
            if valid:
                assert check["staged_binding"]["role"] == role, check
                assert "role runtime is not ready" in check["error"], check
            else:
                assert check["staged_binding"] is None, check
                assert "staged role command is invalid" in check["error"], check

        for role, home in homes.items():
            entry, payload = home / ".safeyolo-command", home / ".safeyolo-command.payload"
            expected = originals[role]
            inert = b'#!/bin/sh\n# exec "$HOME/.safeyolo/safeyolo-coord" supervise --\nexit 0\n'
            mutations = (inert, b"#!/bin/sh\nexit 0\n" + expected,
                         originals["reviewer" if role == "owner" else "owner"],
                         expected.replace(b' supervise "${supervisor_args[@]}" -- ', b" supervise "))
            diagnosis(role, valid=True)
            for changed in mutations:
                entry.write_bytes(changed)
                diagnosis(role, valid=False)
            entry.write_bytes(expected)
            entry.chmod(0o600)
            diagnosis(role, valid=False)
            entry.chmod(0o700)
            # An unattached legitimate payload cannot validate an inert entry.
            payload.write_bytes(expected)
            payload.chmod(0o700)
            entry.write_bytes(inert)
            diagnosis(role, valid=False)
            entry.write_bytes(expected)
            payload.unlink()
            share = home.parent / "config-share"

            def wrap():
                # Use the production wrapper/identity producer, without booting.
                context = {"generation": "stopped-source-fixture", "agent_id": roles(instance)[home.parent.name]["agent_id"]}
                context_input = home.parent / "source-launch-context.json"
                context_input.write_text(json.dumps(context))
                cli(instance, "guest-command", "stage", str(home), str(share),
                    str(instance.root / "assets/guest"), str(context_input))

            wrap()
            wrapper = entry.read_bytes()
            diagnosis(role, valid=True)
            entry.write_bytes(inert)
            diagnosis(role, valid=False)
            entry.write_bytes(wrapper)
            for changed in mutations:
                payload.write_bytes(changed)
                diagnosis(role, valid=False)
            payload.write_bytes(expected)
            # The restored bytes still need the actual recorded file identity.
            diagnosis(role, valid=False)
            wrap()
            diagnosis(role, valid=True)
            context_path = share / "host-launch-context.json"
            context = json.loads(context_path.read_text())
            del context["command_payloads"][".safeyolo-command"]
            context_path.write_text(json.dumps(context))
            diagnosis(role, valid=False)
            wrap()
            diagnosis(role, valid=True)
        assert_no_role_launch(instance)


@pytest.mark.skipif(os.uname().sysname != "Linux", reason="Guest supervision uses Linux process state")
@pytest.mark.parametrize("claude", [False, True])
@pytest.mark.parametrize("command_failure", [False, True], ids=["paused", "failed"])
def test_doctor_rejects_failed_or_paused_command_with_a_healthy_runtime(tmp_path, _binary_cache, monkeypatch, claude, command_failure):
    with prepared(tmp_path, _binary_cache, source_fixture=True, claude=claude) as (instance, _):
        agent = "fixture-forge"
        home = instance.root / "agents" / agent / "home"
        state_path = home / ".safeyolo-command-supervisor.json"
        stop = home / "supervisor.stop"
        context = home.parent / "config-share/host-launch-context.json"
        helper = instance.root / "assets/guest/safeyolo-guest"
        arguments = [str(helper), "--context", str(context), "--state", str(state_path),
                     "--stop", str(stop), "--workspace", str(home)]
        checkpoint = home / ".safeyolo/coord-supervisor-state.json"
        coord = instance.root / "bin/safeyolo-coord"
        initial = subprocess.check_output([str(coord), "read-state", str(checkpoint)])
        subprocess.run([str(coord), "write-state", str(checkpoint)], input=initial, check=True)
        (instance.root / "bin/getent").symlink_to("/usr/bin/getent")
        # Reuse the owned namespace fixture. Only runsc transport and harness
        # preflight are controlled; the real guest check feeds native runtime
        # observation and the actual factory doctor command.
        with _provider_run(instance.root, monkeypatch, name=agent):
            instance.environment.update({key: os.environ[key] for key in ("FAKE_RUN_ID", "SAFEYOLO_RUNSC_ROOT")})
            generation = json.loads(context.read_text())["generation"]
            command = "echo fixture-runtime-failed >&2; exit 77" if command_failure else "exec sleep 60"
            state_path.write_text(json.dumps({
                "schema_version": 1, "name": agent, "generation": generation,
                "supervision_id": "paused-command", "runtime_owner": "guest-pid1",
                "state": "starting", "started_at": 1, "command": command,
                "restart_count": 0, "consecutive_failures": 0,
            }))
            (home.parent / "current-launch.json").write_text(json.dumps({
                "agent_id": roles(instance)[agent]["agent_id"], "name": agent,
                "launch_id": "paused-command", "command": command,
                "launcher": {"kind": "supervisor"}, "state": "managed",
            }))
            runsc = instance.root / "bin/runsc"
            runsc.write_text('''#!/bin/sh
case "$3" in
  state) printf '{"id":"%s","status":"running"}\\n' "$FAKE_RUN_ID" ;;
  exec)
    case "$*" in
      *"safeyolo-guest supervise check"*) exec ''' + shlex.join([*arguments, "supervise", "check"]) + ''' ;;
      *"safeyolo-guest observe check"*) printf 'running\\n' ;;
      *"safeyolo-coord preflight"*) exit 0 ;;
      *) exit 2 ;;
    esac ;;
  *) exit 2 ;;
esac
''')
            runsc.chmod(0o755)
            with tempfile.TemporaryDirectory(prefix="sy1592-") as sockets, socket.socket(socket.AF_UNIX) as listener:
                socket_path = str(Path(sockets) / "role.sock")
                listener.bind(socket_path)
                listener.listen(16)
                config_path = instance.root / "config.toml"
                config = tomlkit.parse(config_path.read_text())
                config["listeners"].append({"agent_id": agent, "socket_path": socket_path})
                config_path.write_text(tomlkit.dumps(config))
                with subprocess.Popen([*arguments, "supervise"]) as supervisor:
                    try:
                        def wait_state(predicate):
                            deadline = time.monotonic() + 5
                            while True:
                                state = json.loads(state_path.read_text())
                                if predicate(state):
                                    return state
                                assert supervisor.poll() is None, "owned supervisor exited"
                                assert time.monotonic() < deadline, state
                                time.sleep(0.02)

                        def diagnose():
                            report = instance.cli("factory", "doctor", "fixture")
                            value = json.loads(report.stdout)
                            # The other two fixture roles have no runtime.
                            assert value["status"] == "not-ready"
                            return next(check for check in value["checks"] if check.get("role") == "owner")

                        if command_failure:
                            failed = wait_state(lambda state: state["state"] == "failed")
                            assert supervisor.wait(timeout=5) == 1
                            assert failed["last_exit_code"] == 77
                            assert "fixture-runtime-failed" in failed["last_stderr"]
                            rejected = diagnose()
                            assert rejected["status"] == "FAIL", rejected
                            assert rejected["runtime"]["runtime_state"] == "running"
                            assert rejected["runtime"]["agent_state"] != "running"
                            assert "fixture-runtime-failed" in rejected["runtime"]["error"]
                            return
                        running = wait_state(lambda state: state["state"] == "running")
                        assert diagnose()["status"] == "PASS"
                        pid = running["command_pid"]
                        os.kill(pid, signal.SIGSTOP)
                        wait_state(lambda state: Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "T")
                        paused = wait_state(lambda state: state["heartbeat_at"] > running["heartbeat_at"])
                        assert paused["command_start_token"] == running["command_start_token"]
                        rejected = diagnose()
                        assert rejected["status"] == "FAIL", rejected
                        assert rejected["runtime"]["runtime_state"] == "running"
                        assert rejected["runtime"]["agent_state"] == "unknown"
                        assert rejected["runtime"]["proxy_attachment"]["state"] == "ready"
                        assert "guest supervisor check failed" in rejected["runtime"]["error"]
                        os.kill(pid, signal.SIGCONT)
                        wait_state(lambda state: Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "S")
                        resumed = diagnose()
                        assert resumed["status"] == "PASS", resumed
                        assert json.loads(state_path.read_text())["command_start_token"] == running["command_start_token"]
                        assert json.loads(state_path.read_text())["restart_count"] == 0
                    finally:
                        stop.write_text("intentional-stop")
                        supervisor.wait(timeout=5)


def test_native_release_preserves_other_work_and_requires_canonical_audit(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        path = instance.root / "agents/fixture-forge/home/.safeyolo/coord-supervisor-state.json"
        executable = instance.root / "bin/safeyolo-coord"
        result = subprocess.run([str(executable), "read-state", str(path)], env=instance.environment, capture_output=True, text=True, check=True)
        state = json.loads(result.stdout)
        selected, other = "https://example.test/issues/one", "https://example.test/issues/two"
        state["safe_cursor"] = 17
        state["thread_id"] = "synthetic-thread"
        state["in_flight"] = [
            {"attention_id": "attn-" + digit * 32, "room_name": "fixture-work", "sender_agent_name": "fixture-relay",
             "sender_agent_id": roles(instance)["fixture-relay"]["agent_id"], "sequence": sequence,
             "body": f"TASK target={target} assignee=fixture-forge", "requires_terminal": True}
            for digit, sequence, target in (("1", 1, selected), ("2", 2, other))
        ]
        written = subprocess.run([str(executable), "write-state", str(path)], input=json.dumps(state), env=instance.environment, capture_output=True, text=True)
        assert written.returncode == 0, written.stderr
        original = path.read_bytes()
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            db.execute("UPDATE memberships SET permissions='receive' WHERE principal_kind='operator'")
        refused = instance.cli("factory", "release", "fixture", "--target", selected, "--yes")
        assert refused.returncode != 0 and "changed agents=" in refused.stderr
        assert path.read_bytes() == original
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            db.execute("UPDATE memberships SET permissions='receive,send' WHERE principal_kind='operator'")
        cli(instance, "factory", "release", "fixture", "--target", selected, "--yes")
        released = json.loads(path.read_text())
        assert released["safe_cursor"] == 17
        assert released["in_flight"] == [state["in_flight"][1]]
        assert released["recent_attention_ids"] == [state["in_flight"][0]["attention_id"]]
        assert released["thread_id"] is None
        assert all(backup.read_bytes() == original for backup in path.parent.glob("*before-release*.json"))
        history = json.loads(cli(instance, "factory", "history", "fixture").stdout)
        assert len(history["messages"]) == 2
        assert all(message["sender_kind"] == "operator" for message in history["messages"])
        assert [message["body"].split(".")[0] for message in history["messages"]] == ["Factory work release requested", "Factory work release completed"]


@pytest.mark.parametrize("claude", [False, True])
def test_doctor_names_missing_role_executable_and_room_permission(tmp_path, _binary_cache, claude):
    with prepared(tmp_path, _binary_cache, claude=claude) as (instance, _):
        executable = instance.root / "agents/fixture-forge/home/.safeyolo/safeyolo-coord"
        saved = executable.with_suffix(".held")
        executable.rename(saved)
        try:
            report = instance.cli("factory", "doctor", "fixture")
            assert report.returncode != 0
            failed = next(item for item in json.loads(report.stdout)["checks"] if item.get("role") == "owner")
            assert failed["status"] == "FAIL" and "required role executable is missing" in failed["error"]
        finally:
            saved.rename(executable)
        agent_id = roles(instance)["fixture-forge"]["agent_id"]
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            db.execute("UPDATE memberships SET permissions='send' WHERE principal_id=? AND room_id=(SELECT room_id FROM rooms WHERE name='fixture-work')", (agent_id,))
        report = instance.cli("factory", "doctor", "fixture")
        assert report.returncode != 0
        failed = next(item for item in json.loads(report.stdout)["checks"] if item.get("role") == "owner")
        assert all(value in failed["error"] for value in ("fixture-work", agent_id, "receive"))
        assert_no_role_launch(instance)
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        (foreign / "coord-supervisor.json").write_text('"private-value-must-stay-unread"')
        directory = instance.root / "agents/fixture-forge/home/.safeyolo"
        held = directory.with_name("held-staging")
        directory.rename(held)
        directory.symlink_to(foreign, target_is_directory=True)
        try:
            report = instance.cli("factory", "doctor", "fixture")
            assert report.returncode != 0
            assert "unsafe agent-local path" in report.stdout
            assert "private-value-must-stay-unread" not in report.stdout + report.stderr
        finally:
            directory.unlink()
            held.rename(directory)


@pytest.mark.parametrize(("error", "wrong_identity", "diagnostic"), [
    ("", False, None),
    (None, False, None),
    ("fixture supervisor failed", False, "fixture supervisor failed"),
    ("", True, "Stored launcher identity does not match agent"),
])
def test_factory_stop_interprets_lifecycle_errors(
    tmp_path, _binary_cache, error, wrong_identity, diagnostic,
):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        agent = "fixture-forge"
        launch = instance.root / "agents" / agent / "current-launch.json"
        record = {"name": agent, "agent_id": roles(instance)[agent]["agent_id"],
                  "launcher": {"kind": "supervisor"}, "state": "stopped", "error": error}
        if wrong_identity:
            record["agent_id"] = "different-fixture-identity"
        launch.write_text(json.dumps(record))
        result = instance.cli("factory", "stop", "fixture")
        if diagnostic is None:
            assert result.returncode == 0, (result.stdout, result.stderr)
            assert "Stopped Factory fixture roles" in result.stdout
        else:
            assert result.returncode != 0, (result.stdout, result.stderr)
            assert "role owner:" in result.stderr and diagnostic in result.stderr
            assert "Stopped Factory" not in result.stdout
        assert json.loads(launch.read_text()) == record
        assert_no_role_launch(instance)


def test_factory_run_does_not_boot_workers_without_coord(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        adopt_source_login(instance)
        cli(instance, "coord", "stop")
        # This stopped, fixture-owned copy is not an active or shared binary.
        binary = instance.root / "data/coord/nats/bin/2.14.5/nats-server"
        binary.write_bytes(b"invalid fixture artifact")
        result = instance.cli("factory", "run", "fixture")
        assert result.returncode != 0 and "NATS executable differs" in result.stderr, (result.stdout, result.stderr)
        assert "Started Factory" not in result.stdout
        assert_no_role_launch(instance)


def test_factory_run_does_not_boot_workers_when_room_provisioning_fails(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        adopt_source_login(instance)
        with sqlite3.connect(instance.root / "data/coord/v0.db") as db:
            db.execute("DELETE FROM memberships WHERE principal_kind='agent'")
            db.execute("CREATE TRIGGER fixture_membership_failure BEFORE INSERT ON memberships WHEN NEW.principal_kind='agent' BEGIN SELECT RAISE(ABORT, 'fixture room provisioning unavailable'); END")
        result = instance.cli("factory", "run", "fixture")
        assert result.returncode != 0 and "fixture room provisioning unavailable" in result.stderr, (result.stdout, result.stderr)
        assert "Started Factory" not in result.stdout
        assert_no_role_launch(instance)


def test_factory_run_requires_confirmation_before_any_role_starts(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
        adopt_source_login(instance)
        for _ in range(2):
            result = instance.cli("factory", "run", "fixture")
            assert result.returncode != 0, (result.stdout, result.stderr)
            assert "factory run fixture --confirm-fresh-identity" in result.stderr
            assert "Started Factory" not in result.stdout
            assert_no_role_launch(instance)
        # A valid earlier role must not start before a later unconfirmed role.
        checkpoint = instance.root / "agents/fixture-relay/home/.safeyolo/coord-supervisor-state.json"
        executable = instance.root / "bin/safeyolo-coord"
        state = json.loads(subprocess.check_output([str(executable), "read-state", str(checkpoint)]))
        state["safe_cursor"] = 91
        state["recent_attention_ids"] = ["attn-" + "c" * 32]
        subprocess.run([str(executable), "write-state", str(checkpoint)], input=json.dumps(state), text=True, check=True)
        saved = checkpoint.read_bytes()
        result = instance.cli("factory", "run", "fixture")
        assert result.returncode != 0 and "role owner:" in result.stderr, result.stderr
        assert checkpoint.read_bytes() == saved  # Run reapplied setup first.
        for name in ("fixture-relay", "fixture-forge", "fixture-lens"):
            directory = instance.root / "agents" / name
            assert not list(directory.glob("runtime*"))
            if name != "fixture-relay":
                assert not (directory / "home/.safeyolo/coord-supervisor-state.json").exists()


def test_factory_setup_interruption_preserves_prepared_roles():
    """First installed phase; provision role-local authentication afterward.

    Supply a fresh owned installed root, dedicated Factory source and a JSON
    role/workspace map. The supported host runtime and pinned NATS must already
    be prepared. This uses real preparation, then interrupts at the existing
    fresh-identity decision before any supervisor or model starts.
    """
    supplied = os.environ.get("SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE")
    if not supplied:
        pytest.skip("requires the separately owned installed guided-setup witness")
    source = Path(supplied).resolve()
    root = Path(os.environ["SAFEYOLO_FACTORY_ACCEPTANCE_ROOT"]).resolve()
    name = tomllib.loads(source.read_text())["name"]
    assert name == os.environ["SAFEYOLO_FACTORY_ACCEPTANCE_NAME"]
    assert not (root / "factories" / name / "approved").exists()
    workspaces = json.loads(os.environ["SAFEYOLO_FACTORY_ACCEPTANCE_WORKSPACES"])
    arguments = ["factory", "setup", str(source)]
    for role, folder in workspaces.items():
        arguments += ["--workspace", f"{role}={folder}"]
    instance = SimpleNamespace(root=root, environment=dict(os.environ))
    with terminal(instance, arguments=arguments) as (process, master, until):
        output = until(b"Approve this exact Factory contract?", timeout=180)
        os.write(master, b"y\n")
        output += until(b"Confirm these fresh identities for this launch?", timeout=180)
        (root / "setup-interruption.log").write_bytes(output)
        process.send_signal(signal.SIGINT)
    configured = tomllib.loads((root / "policy.toml").read_text())["agents"]
    snapshot = (root / "factories" / name / "approved").read_bytes()
    declared = tomllib.loads(source.read_text())["roles"]
    for role in declared.values():
        home = root / "agents" / role["agent"] / "home"
        assert not (home / ".safeyolo/coord-supervisor-state.json").exists()
    resumed = subprocess.run([str(root / "bin/safeyolo"), "--root", str(root), *arguments[:3]],
                             capture_output=True, text=True, timeout=180)
    (root / "setup-interrupted-resume.log").write_text(resumed.stdout + resumed.stderr)
    assert resumed.returncode != 0 and '"status": "checkpoint-required"' in resumed.stdout
    assert "--confirm-fresh-identity" in resumed.stderr
    assert tomllib.loads((root / "policy.toml").read_text())["agents"] == configured
    assert (root / "factories" / name / "approved").read_bytes() == snapshot


CLAUDE_FACTORY_DIRECTION = (
    "This is the installed Claude Factory proof. "
    "Use native Work mutations for assigned work; model text alone cannot complete it. "
    "Do not run a second waiter or change authority."
)


def installed_claude_direction(root, agent, identity, sequence=None):
    """Read the authenticated direction; a retained sequence never sends again."""
    host = [str(root / "bin/safeyolo"), "--root", str(root)]
    room = f"{agent}-agent"
    if sequence is None:
        sent = subprocess.run([*host, "coord", "send", room, CLAUDE_FACTORY_DIRECTION, "--to", agent],
                              capture_output=True, text=True, timeout=60)
        assert sent.returncode == 0, (sent.stdout, sent.stderr)
        acknowledgment = re.fullmatch(
            r"message accepted; sequence=([0-9]+); attention=\S+; delivery=\S+", sent.stdout.strip())
        assert acknowledgment, ("inspect retained history before another send", sent.stdout)
        sequence = int(acknowledgment[1])
    assert sequence > 0, "use the retained positive direction sequence"
    history = subprocess.run([*host, "coord", "history", room, "--since", str(sequence - 1)],
                             capture_output=True, text=True, timeout=60)
    assert history.returncode == 0, (history.stdout, history.stderr)
    messages = [json.loads(line) for line in history.stdout.splitlines()]
    matching = [message for message in messages if message["sequence"] == sequence]
    assert len(matching) == 1, ("direction missing from retained room", room, sequence)
    direction = matching[0]
    assert direction["sender_kind"] == "operator", direction
    assert direction["sender_agent_id"] is None and direction["sender_agent_name"] is None, direction
    assert direction["body"] == CLAUDE_FACTORY_DIRECTION, direction
    assert direction["attention_intent"] == {"mode": "targeted", "agent_ids": [identity]}, direction
    return direction


@pytest.fixture
def claude_direction_envelope():
    return {"sequence": 7, "sender_kind": "operator", "sender_agent_id": None,
            "sender_agent_name": None, "body": CLAUDE_FACTORY_DIRECTION,
            "attention_intent": {"mode": "targeted", "agent_ids": ["ag-proof"]}}


@pytest.mark.parametrize("sequence", [None, 7], ids=["plain-acknowledgment", "readback-only"])
def test_installed_claude_direction_reads_exact_envelope(tmp_path, monkeypatch, claude_direction_envelope, sequence):
    calls = []

    def run(command, **kwargs):
        calls.append(command[3:])
        output = ("message accepted; sequence=7; attention=targeted; delivery=ready\n"
                  if command[4] == "send" else
                  "\n".join(json.dumps(claude_direction_envelope | {"sequence": number}) for number in (7, 8)))
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    assert installed_claude_direction(tmp_path, "proof-claude", "ag-proof", sequence) == claude_direction_envelope
    assert calls[-1] == ["coord", "history", "proof-claude-agent", "--since", "6"]
    assert [command[1] for command in calls] == (["send", "history"] if sequence is None else ["history"])


@pytest.mark.parametrize("changed", [
    None, {"sequence": 8}, {"sender_kind": "agent"}, {"sender_agent_id": "ag-forged"},
    {"body": "operator: " + CLAUDE_FACTORY_DIRECTION},
    {"attention_intent": {"mode": "targeted", "agent_ids": ["ag-other"]}},
    {"attention_intent": {"mode": "room"}},
])
def test_installed_claude_direction_rejects_unmatched_envelope(tmp_path, monkeypatch, claude_direction_envelope, changed):
    def run(command, **kwargs):
        assert command[3:] == ["coord", "history", "proof-claude-agent", "--since", "6"]
        output = "" if changed is None else json.dumps(claude_direction_envelope | changed) + "\n"
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(AssertionError):
        installed_claude_direction(tmp_path, "proof-claude", "ag-proof", 7)


def test_installed_claude_direction_native_readback(tmp_path, _binary_cache):
    policy = COORD_POLICY + '\n[agents.proof-claude]\nagent_id="ag-cccccccccccccccccccccccccccccccc"\n'
    with native_instance(tmp_path, source=policy, agent_api=True) as instance:
        cli(instance, "coord", "start", "--binary", str(_binary_cache))
        try:
            cli(instance, "coord", "room", "create", "proof-claude-agent")
            cli(instance, "coord", "grant", "proof-claude-agent", "proof-claude")
            identity = tomllib.loads(policy)["agents"]["proof-claude"]["agent_id"]
            direction = installed_claude_direction(instance.root, "proof-claude", identity)
            caller = Path(__file__).parents[1] / "blackbox/fixtures/claude-factory/run.py"
            recovered = subprocess.run([sys.executable, str(caller), str(instance.root), "one-role", "readback",
                                        "--direction-sequence", str(direction["sequence"])],
                                       capture_output=True, text=True, timeout=30)
            assert recovered.returncode == 0, (recovered.stdout, recovered.stderr)
            assert json.loads(recovered.stdout)["direction"] == direction
            history = cli(instance, "coord", "history", "proof-claude-agent")
            assert [json.loads(line) for line in history.stdout.splitlines()] == [direction]
        finally:
            cli(instance, "coord", "stop")


def installed_claude_work(root, source, command, role_checks):
    """Use actual guest supervision and native Work, never the model seam."""
    contract = tomllib.loads(Path(source).read_text())
    selected = next((name for name, role in contract["roles"].items()
                     if role.get("harness") == "claude"), None)
    if selected is None:
        return
    assert "work" in contract, "the Claude installed witness needs its native Work policy"
    role = contract["roles"][selected]
    agent = role["agent"]
    identity = next(item["observation"]["agent_id"] for item in role_checks if item["role"] == selected)
    snapshot = (root / "factories" / contract["name"] / "approved").read_text().strip()
    workspace = Path(tomllib.loads((root / "policy.toml").read_text())["agents"][agent]["folder"])
    marker = "claude-factory-" + uuid.uuid4().hex
    artifact = workspace / (marker + ".txt")
    host = [str(root / "bin/safeyolo"), "--root", str(root)]

    def invoke(*args):
        result = subprocess.run([*host, *args], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    installed_claude_direction(root, agent, identity)
    title = (f"Write /workspace/{artifact.name} containing exactly {marker} and a newline. "
             "Retain it, compute SHA256 and publish_work_output with the file URI plus #sha256=<digest>, "
             "omit artifact_base64, execution_outcome succeeded, then explicitly complete_work. "
             "Use native tools, current versions and operation IDs.")
    created = invoke("coord", "work", "create", contract["room"], title,
                     "--assignee", json.dumps({"kind": "agent", "id": identity}),
                     "--factory", json.dumps({"name": contract["name"], "snapshot_id": snapshot}),
                     "--operation-id", marker)
    work_id = created["work"]["work_id"]
    deadline = time.monotonic() + 180
    while True:
        work = invoke("coord", "work", "show", contract["room"], work_id)
        if work["state"] == "done" and work["output"] is not None:
            break
        assert time.monotonic() < deadline, work
        time.sleep(0.5)
    assert work["claim_agent_id"] == identity
    assert work["output"]["producer"] == {"kind": "agent", "id": identity}
    assert work["output"]["execution_outcome"] == "succeeded"
    assert artifact.read_text() == marker + "\n"
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert work["target_ref"].endswith("#sha256=" + digest)
    original_output = work["output"]
    original_generation = work["target_generation"]
    assert work["acceptance_status"]["state"] != "accepted", "producer execution is not independent acceptance"
    refusal = {"room_name": contract["room"], "work_id": work_id,
               "expected_version": work["version"], "expected_generation": work["claim_generation"],
               "expected_target_generation": work["target_generation"],
               "expected_requirements_version": work["acceptance_requirements"]["version"],
               "verdict": "approve", "summary": "Producer cannot independently accept itself",
               "operation_id": marker + "-refuse"}
    guest = "printf %s " + shlex.quote(json.dumps(refusal)) + " | /home/agent/.safeyolo/safeyolo-coord call decide_work_acceptance"
    denied = subprocess.run([*host, "agent", "shell", agent, "-c", guest], capture_output=True, text=True, timeout=30)
    assert denied.returncode != 0
    assert "selected acceptance decider" in denied.stderr or "output producer cannot decide" in denied.stderr
    # The operator independently read the exact retained output. A one-role
    # fixture selects that operator as decider through the ordinary API.
    requirements = work["acceptance_requirements"]
    assert not requirements["checks"] and not requirements["challenges"], "use the finite operator-reviewed fixture"
    invoke("coord", "work", "set-requirements", contract["room"], work_id,
           "--expected-version", str(work["version"]), "--expected-generation", str(work["claim_generation"]),
           "--expected-requirements-version", str(requirements["version"]),
           "--authorities", '[{"kind":"operator","id":"operator"}]',
           "--deciders", '[{"kind":"operator","id":"operator"}]', "--independent", "true",
           "--reason", "The disposable one-role or mixed witness uses independent operator inspection",
           "--operation-id", marker + "-requirements")
    work = invoke("coord", "work", "show", contract["room"], work_id)
    invoke("coord", "work", "decide-acceptance", contract["room"], work_id,
                      "--expected-version", str(work["version"]),
                      "--expected-generation", str(work["claim_generation"]),
                      "--expected-target-generation", str(work["target_generation"]),
                      "--expected-requirements-version", str(work["acceptance_requirements"]["version"]),
                      "--verdict", "approve", "--summary", "Read the retained exact marker and verified its digest",
                      "--operation-id", marker + "-accept")
    accepted = invoke("coord", "work", "show", contract["room"], work_id)
    assert accepted["acceptance_status"]["state"] == "accepted"
    watched = subprocess.run([*host, "agent", "watch", agent, "--once", "--plain", "--history", "100"],
                             capture_output=True, text=True, timeout=30)
    assert watched.returncode == 0, watched.stderr
    assert "harness=claude" in watched.stdout
    assert "session" in watched.stdout.lower() or "turn" in watched.stdout.lower()
    stopped = subprocess.run([*command, "stop", contract["name"]], capture_output=True, text=True, timeout=180)
    assert stopped.returncode == 0, stopped.stderr
    checkpoint = root / "agents" / agent / "home/.safeyolo/coord-supervisor-state.json"
    saved = json.loads(checkpoint.read_text())
    resumed = subprocess.run([*command, "setup", str(source)], capture_output=True, text=True, timeout=600)
    assert resumed.returncode == 0, (resumed.stdout, resumed.stderr)
    assert tomllib.loads((root / "policy.toml").read_text())["agents"][agent]["agent_id"] == identity
    assert json.loads(checkpoint.read_text())["safe_cursor"] >= saved["safe_cursor"]
    current = invoke("coord", "work", "show", contract["room"], work_id)
    assert current["output"] == original_output and current["target_generation"] == original_generation
    assert current["state"] == "done" and current["acceptance_status"]["state"] == "accepted"
    (root / "claude-factory-result.json").write_text(json.dumps({
        "work_id": work_id, "agent_id": identity, "snapshot": snapshot, "output": original_output,
        "target_generation": original_generation, "artifact": str(artifact), "sha256": digest,
        "restarted_without_duplicate_output": True,
    }, indent=2) + "\n")


def factory_setup_result(stdout):
    """Read setup's prepared and running JSON results in emission order."""
    decoder = json.JSONDecoder()
    remaining = stdout.lstrip()
    results = []
    while remaining:
        value, end = decoder.raw_decode(remaining)
        results.append(value)
        remaining = remaining[end:].lstrip()
    assert results and results[-1]["status"] == "running", results
    return results


def assert_restarted_claude_policy(before, after, agent, run_id):
    """Permit the same approved credential only within the replacement run."""
    before, after = dict(before), dict(after)
    old_grants = before.pop("credential_grants", {})
    new_grants = after.pop("credential_grants", {})
    assert after == before, "required agent bindings changed"
    assert all(new_grants.get(key) == value for key, value in old_grants.items()), "prior credential grants changed"
    binding = {"agent": agent, "agent_id": before["agent_id"], "run_id": run_id}
    for key, grant in new_grants.items():
        if key not in old_grants:
            assert any(grant == {**prior, "approval_id": key, "beneficiary": binding,
                                 "action": {**prior["action"], "run": binding}}
                       for prior in old_grants.values() if prior["option"] == "run"), "unexpected credential grant"


def installed_claude_pending_work(root, source, *, session_recovery=False):
    """Pause one new native Work at a file gate, then restart its existing role."""
    contract = tomllib.loads(source.read_text())
    role = next(role for role in contract["roles"].values() if role.get("harness") == "claude")
    agent = role["agent"]
    policy = tomllib.loads((root / "policy.toml").read_text())["agents"][agent]
    identity = policy["agent_id"]
    snapshot = (root / "factories" / contract["name"] / "approved").read_text().strip()
    workspace = Path(policy["folder"])
    marker = ("claude-session-recovery-" if session_recovery else "claude-pending-") + snapshot
    artifact, started, release = (workspace / (marker + suffix) for suffix in (".txt", ".started", ".release"))
    argument_report = workspace / (marker + ".argument.json")
    paths = (artifact, started, release, argument_report) if session_recovery else (artifact, started, release)
    assert not any(path.exists() for path in paths), "inspect the retained pending attempt before retrying"
    host = [str(root / "bin/safeyolo"), "--root", str(root)]
    command = [*host, "factory"]

    def invoke(*args):
        result = subprocess.run([*host, *args], capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, (args, result.stdout, result.stderr)
        return json.loads(result.stdout)

    def permissions():
        with sqlite3.connect(root / "data/coord/v0.db") as db:
            return db.execute("SELECT room_id, permissions FROM memberships "
                              "WHERE principal_id=? AND revoked_at IS NULL ORDER BY room_id", (identity,)).fetchall()

    purpose = "C3 saved-session recovery" if session_recovery else "Pending-Work restart"
    start_instruction = (f"Write /workspace/{started.name} containing exactly {marker} and a newline. ")
    result_instruction = f"write /workspace/{artifact.name} containing exactly {marker} and a newline. "
    if session_recovery:
        start_instruction = (
            "First exercise the remaining native argument-failure case: run the installed claude --version and "
            "claude --safeyolo-c3-unknown-argument once, without a model prompt. "
            f"Retain /workspace/{argument_report.name} as JSON with cli_version, argument, exit_code and diagnostic "
            "from the actual commands; keep only the unknown-option diagnostic, no credentials. "
            "Require a nonzero exit and an unknown-argument diagnostic naming that flag; report a failure honestly. "
            "On redelivery reuse this report instead of repeating the command. " + start_instruction)
        result_instruction = f"copy the complete argument report unchanged to /workspace/{artifact.name}. "
    title = (f"{purpose} qualification. Claim this Work once. {start_instruction}"
             f"Then use a foreground shell loop to wait until "
             f"/workspace/{release.name} exists. The operator will stop and restart this role during that wait. "
             "On redelivery, read this original Work and reuse its claim and existing files. Do not create other Work. "
             f"Once the release file exists, {result_instruction}"
             "Retain it, compute SHA256 and publish_work_output with its file URI plus #sha256=<digest>, "
             "omit artifact_base64, execution_outcome succeeded, then explicitly complete_work. "
             "Use native tools, current versions and operation IDs. Read existing output before any repeated publication.")
    created = invoke("coord", "work", "create", contract["room"], title,
                     "--assignee", json.dumps({"kind": "agent", "id": identity}),
                     "--factory", json.dumps({"name": contract["name"], "snapshot_id": snapshot}),
                     "--operation-id", marker)
    work_id = created["work"]["work_id"]
    work = invoke("coord", "work", "show", contract["room"], work_id)
    assert work["state"] == "open" and work["claim_generation"] == 0, "inspect the original attempt; do not replay it"
    result_path = root / ("claude-session-recovery-result.json" if session_recovery else "claude-pending-work-result.json")
    evidence = {"work_id": work_id, "agent_id": identity, "snapshot": snapshot, "created": work}
    result_path.write_text(json.dumps(evidence, indent=2) + "\n")
    home = root / "agents" / agent / "home"
    checkpoint = home / ".safeyolo/coord-supervisor-state.json"
    retained = home / marker
    with retained.open("x") as output:
        output.write(marker + "\n")
    authority = permissions()
    assert authority, "the selected role must have current room authority"

    def setup():
        result = subprocess.run([*command, "setup", str(source)], capture_output=True, text=True, timeout=600)
        evidence.setdefault("setup_results", []).append({"returncode": result.returncode,
                                                        "stdout": result.stdout, "stderr": result.stderr})
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")
        assert result.returncode == 0, (result.stdout, result.stderr)
        factory_setup_result(result.stdout)

    try:
        setup()
        deadline = time.monotonic() + 180
        while True:
            work = invoke("coord", "work", "show", contract["room"], work_id)
            if started.exists() and work["state"] == "claimed":
                break
            assert time.monotonic() < deadline, work
            time.sleep(0.5)
        assert started.read_text() == marker + "\n" and not artifact.exists()
        assert work["claim_agent_id"] == identity and work["claim_generation"] == 1
        assert work["output"] is None and work["target_generation"] == 0
        running = json.loads(checkpoint.read_text())
        assert running["phase"] == "running" and running["owned_process"] is not None
        stopped = subprocess.run([*command, "stop", contract["name"]], capture_output=True, text=True, timeout=180)
        assert stopped.returncode == 0, stopped.stderr
        saved = json.loads(checkpoint.read_text())
        pending = invoke("coord", "work", "show", contract["room"], work_id)
        # Preserve the reached interruption before attempting its resume.
        evidence.update(checkpoint_before_stop=running, pending_after_stop=pending, checkpoint_after_stop=saved)
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")
        assert saved["thread_id"] and any(item["action"]["work_id"] == work_id for item in saved["native_in_flight"])
        assert pending == work, "stopping the role must not settle or change its claimed Work"
        setup()
        deadline = time.monotonic() + 180
        while True:
            resumed = json.loads(checkpoint.read_text())
            if (resumed["phase"] == "running" and resumed["owned_process"] is not None
                    and resumed["owned_process"]["token"] != running["owned_process"]["token"]):
                break
            assert time.monotonic() < deadline, resumed
            time.sleep(0.5)
        evidence["checkpoint_resumed_pending"] = resumed
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")
        assert resumed["thread_id"] == saved["thread_id"], "interrupted Claude session was replaced"
        assert any(item["action"]["work_id"] == work_id for item in resumed["native_in_flight"])
        release.write_text("resume the original pending Work\n")
        deadline = time.monotonic() + 180
        while True:
            completed = invoke("coord", "work", "show", contract["room"], work_id)
            if completed["state"] == "done" and completed["output"] is not None:
                break
            assert time.monotonic() < deadline, completed
            time.sleep(0.5)
        evidence["completed"] = completed
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")
        assert completed["claim_agent_id"] == identity and completed["claim_generation"] == 1
        assert completed["target_generation"] == 1
        assert completed["output"]["producer"] == {"kind": "agent", "id": identity}
        assert completed["output"]["execution_outcome"] == "succeeded"
        if session_recovery:
            failure = json.loads(artifact.read_text())
            evidence["native_argument_failure"] = failure
            result_path.write_text(json.dumps(evidence, indent=2) + "\n")
            assert (failure["cli_version"] and isinstance(failure["exit_code"], int) and failure["exit_code"] != 0
                    and failure["argument"] == "--safeyolo-c3-unknown-argument"
                    and failure["argument"] in failure["diagnostic"]
                    and "unknown" in failure["diagnostic"].lower()), "native Claude unknown argument was not rejected"
            assert artifact.read_bytes() == argument_report.read_bytes(), "native argument report changed"
        else:
            assert artifact.read_text() == marker + "\n"
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        assert completed["target_ref"] == "file:///workspace/" + artifact.name + "#sha256=" + digest
        deadline = time.monotonic() + 60
        while True:
            current = json.loads(checkpoint.read_text())
            if not any(item["action"]["work_id"] == work_id for item in current.get("native_in_flight", [])):
                break
            assert time.monotonic() < deadline, current
            time.sleep(0.5)
        current_policy = tomllib.loads((root / "policy.toml").read_text())["agents"][agent]
        report = invoke("factory", "doctor", contract["name"])
        runtime = next(item["observation"]["runtime"] for item in report["checks"]
                       if item["component"] == "role" and item["observation"]["agent_id"] == identity)
        evidence.update(completed=completed, checkpoint_after_resume=current, sha256=digest,
                        policy_before=policy, policy_after=current_policy, runtime_after_resume=runtime)
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")
        assert current["safe_cursor"] >= saved["safe_cursor"]
        assert_restarted_claude_policy(policy, current_policy, agent, runtime["run_id"])
        assert permissions() == authority and retained.read_text() == marker + "\n"
        assert (root / "factories" / contract["name"] / "approved").read_text().strip() == snapshot
        staged = json.loads((home / ".safeyolo/coord-supervisor.json").read_text())
        assert staged["factory"]["snapshot_id"] == snapshot and staged["harness"] == "claude"
        assert invoke("coord", "work", "show", contract["room"], work_id)["output"] == completed["output"]
        evidence.update(completed=completed, checkpoint_after_resume=current, home_and_authority_retained=True, sha256=digest)
        result_path.write_text(json.dumps(evidence, indent=2) + "\n")
    finally:
        stopped = subprocess.run([*command, "stop", contract["name"]], capture_output=True, text=True, timeout=180)
        assert stopped.returncode == 0, stopped.stderr


@pytest.mark.parametrize("state", ["claimed", "done"])
@pytest.mark.parametrize("session_recovery", [False, True])
def test_pending_claude_caller_refuses_replaying_started_work(tmp_path, monkeypatch, state, session_recovery):
    source = Path(__file__).parents[1] / "blackbox/fixtures/claude-factory/one-role.toml"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    approved = tmp_path / "factories/claude-one/approved"
    approved.parent.mkdir(parents=True)
    approved.write_text("a" * 64 + "\n")
    (tmp_path / "policy.toml").write_text(f'[agents.proof-claude]\nagent_id="ag-proof"\nfolder={json.dumps(str(workspace))}\n')
    calls = []

    def run(command, **kwargs):
        calls.append(command[3:6])
        assert command[3:6] in (["coord", "work", "create"], ["coord", "work", "show"])
        response = {"work": {"work_id": "work-retained"}} if command[5] == "create" else {"state": state, "claim_generation": 1}
        return SimpleNamespace(returncode=0, stdout=json.dumps(response), stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(AssertionError, match="inspect the original attempt"):
        installed_claude_pending_work(tmp_path, source, session_recovery=session_recovery)
    assert calls == [["coord", "work", "create"], ["coord", "work", "show"]]
    assert not list(workspace.iterdir())


@pytest.mark.parametrize(("session_recovery", "defect"), [
    (session, defect) for session in (False, True)
    for defect in (None, "setup-json", "session", "policy", "credential", "grant-scope", "prior-grant")
] + [(True, "native-argument")])
def test_pending_claude_caller_observes_setup_recovery_and_scoped_grants(tmp_path, monkeypatch, defect, session_recovery):
    """Exercise the caller with setup's JSON sequence and completed idle state."""
    source = Path(__file__).parents[1] / "blackbox/fixtures/claude-factory/one-role.toml"
    agent, identity, snapshot = "proof-claude", "ag-proof", "a" * 64
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    home = tmp_path / "agents" / agent / "home"
    (home / ".safeyolo").mkdir(parents=True)
    checkpoint = home / ".safeyolo/coord-supervisor-state.json"
    (home / ".safeyolo/coord-supervisor.json").write_text(json.dumps({
        "harness": "claude", "factory": {"snapshot_id": snapshot}}))
    approved = tmp_path / "factories/claude-one/approved"
    approved.parent.mkdir(parents=True)
    approved.write_text(snapshot + "\n")
    binding = {"agent": agent, "agent_id": identity, "run_id": "old-run"}
    grant = {"approval_id": "apr-old", "beneficiary": binding, "option": "run",
             "action": {"kind": "credential_allow", "agent": agent, "agent_id": identity,
                        "run": binding, "host": "api.anthropic.com", "credentials": ["hmac:fixture"]}}
    policy = {"agents": {agent: {"agent_id": identity, "folder": str(workspace),
                                 "services": {"claude": ["inference"]}, "network_slot": 2,
                                 "credential_grants": {"apr-old": grant}}}}
    policy_path = tmp_path / "policy.toml"
    policy_path.write_text(tomlkit.dumps(policy))
    database = tmp_path / "data/coord/v0.db"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE memberships (room_id TEXT, permissions TEXT, principal_id TEXT, revoked_at INTEGER)")
        db.execute("INSERT INTO memberships VALUES ('rm-proof', 'send,receive', ?, NULL)", (identity,))
    marker = ("claude-session-recovery-" if session_recovery else "claude-pending-") + snapshot
    accepted = []
    if session_recovery:
        accepted = [workspace / ("claude-pending-" + snapshot + suffix) for suffix in (".txt", ".started", ".release")]
        accepted += [home / ("claude-pending-" + snapshot), tmp_path / "claude-pending-work-result.json"]
        for path in accepted:
            path.write_text("accepted pending-work proof\n")
    action = {"action": {"work_id": "work-pending"}}
    work = {"work_id": "work-pending", "state": "open", "claim_generation": 0, "output": None, "target_generation": 0}
    setup_count, stop_count = 0, 0

    def run(command, **kwargs):
        nonlocal setup_count, stop_count, work
        args = command[3:]
        if args[:3] == ["coord", "work", "create"]:
            assert args[-1] == marker
            assert ("C3 saved-session recovery" in args[4]) == session_recovery
            value = {"work": {"work_id": work["work_id"]}}
        elif args[:3] == ["coord", "work", "show"]:
            if setup_count == 2 and (workspace / (marker + ".release")).exists():
                artifact = workspace / (marker + ".txt")
                artifact.write_text((workspace / (marker + ".argument.json")).read_text()
                                    if session_recovery else marker + "\n")
                digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
                work = {**work, "state": "done", "target_generation": 1,
                        "target_ref": "file:///workspace/" + artifact.name + "#sha256=" + digest,
                        "output": {"producer": {"kind": "agent", "id": identity}, "execution_outcome": "succeeded"}}
                checkpoint.write_text(json.dumps({"phase": "idle", "thread_id": None, "safe_cursor": 14,
                                                  "owned_process": None, "native_in_flight": []}))
            value = work
        elif args[:2] == ["factory", "setup"]:
            setup_count += 1
            work = {**work, "state": "claimed", "claim_agent_id": identity, "claim_generation": 1}
            if session_recovery and setup_count == 1:
                (workspace / (marker + ".argument.json")).write_text(json.dumps({
                    "cli_version": "2.1.317", "argument": "--safeyolo-c3-unknown-argument",
                    "exit_code": 0 if defect == "native-argument" else 1,
                    "diagnostic": "error: unknown option '--safeyolo-c3-unknown-argument'"}))
            (workspace / (marker + ".started")).write_text(marker + "\n")
            checkpoint.write_text(json.dumps({"phase": "running", "thread_id": "other" if defect == "session" and setup_count == 2 else "original",
                                              "safe_cursor": 11, "owned_process": {"pid": setup_count, "token": f"birth-{setup_count}"},
                                              "native_in_flight": [action]}))
            if setup_count == 2:
                current = json.loads(json.dumps(policy))
                new_binding = {**binding, "run_id": "new-run"}
                current["agents"][agent]["credential_grants"]["apr-new"] = {
                    **grant, "approval_id": "apr-new", "beneficiary": new_binding,
                    "action": {**grant["action"], "run": new_binding}}
                if defect == "policy":
                    current["agents"][agent]["network_slot"] = 3
                if defect == "credential":
                    current["agents"][agent]["credential_grants"]["apr-new"]["action"]["host"] = "other.example"
                if defect == "grant-scope":
                    new_binding["run_id"] = "other-run"
                if defect == "prior-grant":
                    del current["agents"][agent]["credential_grants"]["apr-old"]
                policy_path.write_text(tomlkit.dumps(current))
            return SimpleNamespace(returncode=0, stdout='{"status":"prepared"}\n' +
                                   ('truncated {' if defect == "setup-json" else '{"status":"running"}\n'), stderr="")
        elif args[:2] == ["factory", "doctor"]:
            value = {"checks": [{"component": "role", "observation": {"agent_id": identity, "runtime": {"run_id": "new-run"}}}]}
        else:
            assert args[:2] == ["factory", "stop"], args
            stop_count += 1
            value = {}
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")

    monkeypatch.setattr(subprocess, "run", run)
    if defect == "setup-json":
        with pytest.raises(json.JSONDecodeError):
            installed_claude_pending_work(tmp_path, source, session_recovery=session_recovery)
    elif defect:
        message = {"session": "interrupted Claude session was replaced", "policy": "required agent bindings changed",
                   "credential": "unexpected credential grant", "grant-scope": "unexpected credential grant",
                   "prior-grant": "prior credential grants changed",
                   "native-argument": "native Claude unknown argument was not rejected"}[defect]
        with pytest.raises(AssertionError, match=message):
            installed_claude_pending_work(tmp_path, source, session_recovery=session_recovery)
    else:
        installed_claude_pending_work(tmp_path, source, session_recovery=session_recovery)
    result = "claude-session-recovery-result.json" if session_recovery else "claude-pending-work-result.json"
    evidence = json.loads((tmp_path / result).read_text())
    assert all(path.read_text() == "accepted pending-work proof\n" for path in accepted)
    assert evidence["work_id"] == "work-pending" and evidence["setup_results"]
    assert stop_count == (1 if defect == "setup-json" else 2)
    if defect == "session":
        assert evidence["checkpoint_resumed_pending"]["thread_id"] == "other"
        assert not (workspace / (marker + ".release")).exists()
    elif defect not in ("setup-json", "native-argument"):
        assert evidence["checkpoint_after_resume"]["thread_id"] is None
        expected_run = "other-run" if defect == "grant-scope" else "new-run"
        assert evidence["policy_after"]["credential_grants"]["apr-new"]["beneficiary"]["run_id"] == expected_run
        assert evidence.get("home_and_authority_retained", False) == (defect is None)


def test_factory_pending_claude_work_survives_restart():
    """Interrupt one new claimed Work in the existing installed witness."""
    supplied = os.environ.get("SAFEYOLO_FACTORY_ACCEPTANCE_ROOT")
    source = os.environ.get("SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE")
    if not supplied or not source:
        pytest.skip("requires a prepared installed Factory witness and its Claude contract source")
    source = Path(source)
    selected = tomllib.loads(source.read_text())
    if not any(role.get("harness") == "claude" for role in selected["roles"].values()):
        pytest.skip("requires a Claude role in the selected Factory contract")
    if os.environ.get("SAFEYOLO_FACTORY_SESSION_RECOVERY") == "1":
        installed_claude_pending_work(Path(supplied).resolve(), source, session_recovery=True)
    else:
        installed_claude_pending_work(Path(supplied).resolve(), source)


@pytest.mark.parametrize("source_selection", ["named", "codex-pi", "claude", "claude-session"])
def test_pending_claude_case_preserves_other_factory_selections(tmp_path, monkeypatch, source_selection):
    """Only dispatch pending recovery when the selected witness has its inputs."""
    root = tmp_path / "installed"
    monkeypatch.setenv("SAFEYOLO_FACTORY_ACCEPTANCE_ROOT", str(root))
    monkeypatch.setenv("SAFEYOLO_FACTORY_ACCEPTANCE_NAME", "fixture")
    monkeypatch.setenv("SAFEYOLO_FACTORY_SESSION_RECOVERY", "1" if source_selection == "claude-session" else "0")
    monkeypatch.delenv("SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE", raising=False)
    source = None
    if source_selection != "named":
        source = contract(tmp_path / "contract", claude=source_selection in ("claude", "claude-session"))
        monkeypatch.setenv("SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE", str(source))
    calls = []
    monkeypatch.setitem(globals(), "installed_claude_pending_work", lambda *args, **kwargs: calls.append((args, kwargs)))
    if source_selection in ("claude", "claude-session"):
        test_factory_pending_claude_work_survives_restart()
        assert calls == [((root.resolve(), source), {"session_recovery": True} if source_selection == "claude-session" else {})]
    else:
        with pytest.raises(pytest.skip.Exception, match="requires"):
            test_factory_pending_claude_work_survives_restart()
        assert calls == []
    assert not root.exists()


def test_factory_run_executes_staged_worker_commands():
    """Run only on the explicit disposable installed Linux or macOS host."""
    supplied = os.environ.get("SAFEYOLO_FACTORY_ACCEPTANCE_ROOT")
    if not supplied:
        pytest.skip("requires the separately owned, prepared installed Factory witness")
    root = Path(supplied).resolve()
    executable = root / "bin/safeyolo"
    name = os.environ["SAFEYOLO_FACTORY_ACCEPTANCE_NAME"]
    command = [str(executable), "--root", str(root), "factory"]
    source = os.environ.get("SAFEYOLO_FACTORY_ACCEPTANCE_SOURCE")
    start = ["setup", source, "--confirm-fresh-identity"] if source else ["run", name]
    try:
        result = subprocess.run([*command, *start], capture_output=True, text=True, timeout=600)
        (root / "setup-start.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert ('"status": "running"' if source else "Started Factory") in result.stdout
        report = subprocess.run([*command, "doctor", name], capture_output=True, text=True, timeout=180)
        (root / "setup-doctor.log").write_text(report.stdout + report.stderr)
        assert report.returncode == 0, report.stderr
        observed = json.loads(report.stdout)
        assert observed["status"] == "ready"
        role_checks = [item for item in observed["checks"] if item["component"] == "role"]
        expected = len(tomllib.loads(Path(source).read_text())["roles"]) if source else 3
        assert len(role_checks) == expected and all(item["status"] == "PASS" for item in role_checks)
        assert len({item["observation"]["agent_id"] for item in role_checks}) == expected
        assert all(item["observation"]["runtime"]["agent_state"] == "running" for item in role_checks)
        if source:
            identities = {item["role"]: (item["observation"]["agent_id"], item["observation"]["runtime"]["run_id"],
                                         item["observation"]["runtime"]["launch_id"])
                          for item in role_checks}
            returned = subprocess.run([*command, "setup", source], capture_output=True, text=True, timeout=180)
            (root / "setup-return.log").write_text(returned.stdout + returned.stderr)
            assert returned.returncode == 0, (returned.stdout, returned.stderr)
            report = subprocess.run([*command, "doctor", name], capture_output=True, text=True, timeout=180)
            (root / "setup-return-doctor.log").write_text(report.stdout + report.stderr)
            assert report.returncode == 0, (report.stdout, report.stderr)
            current = json.loads(report.stdout)
            assert current["status"] == "ready"
            assert identities == {item["role"]: (item["observation"]["agent_id"], item["observation"]["runtime"]["run_id"],
                                                 item["observation"]["runtime"]["launch_id"])
                                  for item in current["checks"] if item["component"] == "role"}
            installed_claude_work(root, source, command, role_checks)
            original = (root / "factories" / name / "approved").read_bytes()
            changed = tomlkit.parse(Path(source).read_text())
            changed["room"] += "-unapproved"
            changed_source = Path(source).with_name("setup-unapproved.toml")
            with changed_source.open("x") as output:
                output.write(tomlkit.dumps(changed))
            refused = subprocess.run([*command, "setup", str(changed_source)], capture_output=True, text=True, timeout=180)
            (root / "setup-unapproved.log").write_text(refused.stdout + refused.stderr)
            assert refused.returncode != 0 and '"status": "approval-required"' in refused.stdout
            assert (root / "factories" / name / "approved").read_bytes() == original
            stopped = subprocess.run([*command, "stop", name], capture_output=True, text=True, timeout=180)
            assert stopped.returncode == 0, stopped.stderr
            resumed = subprocess.run([*command, "setup", source], capture_output=True, text=True, timeout=600)
            (root / "setup-checkpoint-resume.log").write_text(resumed.stdout + resumed.stderr)
            assert resumed.returncode == 0 and '"status": "running"' in resumed.stdout, (resumed.stdout, resumed.stderr)
    finally:
        stopped = subprocess.run([*command, "stop", name], capture_output=True, text=True, timeout=180)
        assert stopped.returncode == 0, stopped.stderr
