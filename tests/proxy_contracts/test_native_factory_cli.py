"""Installed Factory entry and staged consumers, without a guest or model launch.

The optional launch test needs an explicitly prepared disposable Ubuntu host.
It is separate from these source fixtures and the paid W4 work witness.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import tomllib
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.proxy_contracts.test_native_policy_cli import native_instance


def contract(directory, *, mixed=True):
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
    assert result.returncode == 0, (result.stdout, result.stderr)
    return result


@contextmanager
def prepared(directory, nats_binary):
    with native_instance(directory, source=None, agent_api=True) as instance:
        # Ordinary shell utilities are production prerequisites. No Python,
        # package import path or source-checkout helper is in the command PATH.
        tools = directory / "tools"
        tools.mkdir()
        for name in ("bash", "env", "cp", "chmod", "mkdir", "install", "stat", "id",
                     "dirname", "cat", "tail", "grep", "sed", "awk", "readlink",
                     "ln", "mv", "rm", "mktemp", "sha256sum", "git", "openssl"):
            executable = shutil.which(name)
            assert executable is not None, name
            (tools / name).symlink_to(executable)
        instance.environment["PATH"] = os.pathsep.join((str(instance.root / "bin"), str(tools)))
        instance.environment["SAFEYOLO_NATS_TEST_INSTANCE"] = "1"
        for name in ("SAFEYOLO_COORD_EXECUTABLE", "SAFEYOLO_COORD_GUEST_BINARY",
                     "SAFEYOLO_FACTORY_SNAPSHOT", "SAFEYOLO_FACTORY_ROLE",
                     "SAFEYOLO_CODEX_COORD_SUPERVISOR", "SAFEYOLO_PI_COORD_SUPERVISOR"):
            instance.environment.pop(name, None)
        source = contract(directory / "contract")
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


def test_installed_prepare_stages_codex_pi_and_retains_state_and_peer_grants(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, workspaces):
        assert not list(instance.root.rglob("*.py"))
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
            assert 'exec "$HOME/.safeyolo/safeyolo-coord" supervise --' in payload.read_text()
            runtime = home / ".safeyolo/safeyolo-coord"
            with runtime.open("rb") as handle:
                assert hashlib.file_digest(handle, "sha256").hexdigest() == (instance.root / "assets/guest/safeyolo-coord.sha256").read_text().strip()
            assert 'safeyolo-coord" repo-map "$@"' in (home / ".safeyolo/repo-map").read_text()
            assert not (home / ".agents/skills/safeyolo-lab-controller").is_symlink()
        pi = instance.root / "agents/fixture-lens/home"
        assert (pi / ".pi/agent/extensions/safeyolo-coord.ts").read_bytes() == (instance.root / "assets/contrib/pi-coord-extension.ts").read_bytes()
        assert (pi / ".pi/agent/skills/safeyolo").readlink() == Path("/safeyolo/skills/safeyolo")
        codex_home = instance.root / "agents/fixture-relay/home/.codex"
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
        (repository / os.fsdecode(b"filename-\xff.rs")).write_text("fn byte_filename() {}\n")
        before = source.read_bytes()
        result = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "repo-map", str(repository), "--query", "repair_fixture Factory", "--hints", str(instance.root / "assets/repo-map.toml")], env=environment, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert all(value in result.stdout for value in ("symbols=lexical", "repair_fixture", "return 1", "GUIDANCE"))
        assert source.read_bytes() == before
        mapped = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "repo-map", str(repository)], env=environment, capture_output=True, text=True, timeout=10)
        assert mapped.returncode == 0 and "binary" in mapped.stdout and "byte_filename" in mapped.stdout
        (repository / "pyproject.toml").write_text('[project]\nname="safeyolo"\n')
        staged = instance.root / "agents/fixture-forge/home/.safeyolo/safeyolo-coord"
        fallback = subprocess.run([str(staged), "repo-map", str(repository), "--query", "Factory"], env=environment, capture_output=True, text=True, timeout=10)
        assert fallback.returncode == 0 and "GUIDANCE" in fallback.stdout


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


def test_doctor_names_missing_role_executable_and_room_permission(tmp_path, _binary_cache):
    with prepared(tmp_path, _binary_cache) as (instance, _):
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


def test_factory_run_executes_staged_worker_commands():
    """Run only on the explicit disposable installed Ubuntu acceptance root."""
    supplied = os.environ.get("SAFEYOLO_FACTORY_ACCEPTANCE_ROOT")
    if not supplied:
        pytest.skip("requires the separately owned, prepared installed Factory witness")
    root = Path(supplied).resolve()
    executable = root / "bin/safeyolo"
    name = os.environ["SAFEYOLO_FACTORY_ACCEPTANCE_NAME"]
    command = [str(executable), "--root", str(root), "factory"]
    try:
        result = subprocess.run([*command, "run", name], capture_output=True, text=True, timeout=180)
        assert result.returncode == 0 and "Started Factory" in result.stdout, (result.stdout, result.stderr)
        report = subprocess.run([*command, "doctor", name], capture_output=True, text=True, timeout=180)
        assert report.returncode == 0, report.stderr
        observed = json.loads(report.stdout)
        assert observed["status"] == "ready"
        role_checks = [item for item in observed["checks"] if item["component"] == "role"]
        assert len(role_checks) == 3 and all(item["status"] == "PASS" for item in role_checks)
        assert len({item["observation"]["agent_id"] for item in role_checks}) == 3
        assert all(item["observation"]["runtime"]["agent_state"] == "running" for item in role_checks)
    finally:
        stopped = subprocess.run([*command, "stop", name], capture_output=True, text=True, timeout=180)
        assert stopped.returncode == 0, stopped.stderr
