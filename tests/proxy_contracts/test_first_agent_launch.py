"""First-launch host consent and the shared numbered operator interaction.

The proxy and policy effects are real. These controls do not claim a booted
guest or Claude-provider result; those require the authorized installed witness.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_coord_operator import terminal
from tests.proxy_contracts.test_native_policy_cli import native_inputs, native_instance

AGENTS = '''
[agents.alice]
agent_id="ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[agents.bob]
agent_id="ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''
REPO = Path(__file__).resolve().parents[2]


def _wait_for_active_policy(instance):
    deadline = time.monotonic() + 4
    while not instance.show()["saved_matches_active"]:
        assert time.monotonic() < deadline
        time.sleep(0.02)


@pytest.mark.parametrize("kind", ["network", "credential"])
@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_first_run_numbered_decisions_show_and_enforce_their_real_scope(tmp_path, kind, decision):
    network = "prompt" if kind == "network" else "allow"
    policy = f'''budget=12000
[hosts]
"*"={{egress="{network}",unknown_creds="prompt"}}
[credential.synthetic]
match=["first-launch-key"]
headers=["authorization"]
''' + AGENTS
    with origin_server(capture_heads=True) as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/first-launch"
        headers = {"Authorization": "Bearer first-launch-key"} if kind == "credential" else {}
        status, _, _ = request(instance.paths["alice"], target, headers=headers)
        assert status == 428 and origin.accepts == 0
        with terminal(instance, ["approvals", "review", "--agent", "alice"]) as (process, master, until):
            output = until(b"Request number")
            os.write(master, b"1\n")
            output += until(b"approve / reject")
            if kind == "network":
                assert b"Allow reusable network access for alice" in output
                assert b"until explicitly removed" in output
            else:
                assert b"all agents in this instance, including future agents" in output
                assert b"shared persistent policy" in output
                assert b"first-launch-key" not in output
            os.write(master, decision.encode() + b"\n")
            output += until(b"No pending requests")
            assert process.wait(timeout=5) == 0
            assert b"first-launch-key" not in output
        _wait_for_active_policy(instance)
        status, _, body = request(instance.paths["alice"], target, headers=headers)
        if decision == "reject":
            assert status == 428 and origin.accepts == 0
        else:
            assert (status, body) == (200, b"hello")
            other_status, _, _ = request(instance.paths["bob"], target, headers=headers)
            assert other_status == (428 if kind == "network" else 200)
            assert origin.accepts == (1 if kind == "network" else 2)


def test_credential_picker_does_not_attribute_old_requests_to_a_recreated_name(tmp_path):
    policy = '''budget=12000
[hosts]
"*"={egress="allow",unknown_creds="prompt"}
[credential.synthetic]
match=["first-launch-key"]
headers=["authorization"]
''' + AGENTS
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/identity"
        status, _, _ = request(instance.paths["alice"], target, headers={"Authorization": "Bearer first-launch-key"})
        assert status == 428 and origin.accepts == 0
        pending = instance.admin("GET", "/admin/approvals")["approvals"]
        identifier = pending[0]["request_id"]
        instance.apply(policy.replace("ag-" + "a" * 32, "ag-" + "c" * 32))
        refused = instance.cli("approvals", "approve", identifier, "--agent", "alice")
        assert refused.returncode != 0 and "selected current agent" in refused.stderr
        assert origin.accepts == 0 and not instance.show()["effective"]["hosts"].get("127.0.0.1")


@pytest.mark.parametrize("choice", ["decline", "interrupt"])
def test_launch_refusal_has_no_setup_service_or_agent_effect(tmp_path, choice):
    artifacts, _, _ = native_inputs()
    binary = artifacts / "safeyolo"
    root, workspace = tmp_path / "installed", tmp_path / "workspace"
    workspace.mkdir()
    # This control stops before staging. No guest or provider input is used.
    initialized = subprocess.run([str(binary), "--root", str(root), "init"], capture_output=True, text=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(binary.resolve())
    scripts = root / "assets/contrib"
    scripts.mkdir(parents=True)
    shutil.copy2(REPO / "contrib/claude-host-setup.sh", scripts)
    instance = SimpleNamespace(root=root, environment={**os.environ, "TERM": "xterm-256color"})
    policy = (root / "policy.toml").read_bytes()
    with terminal(instance, ["agent", "launch"], cwd=workspace) as (process, master, until):
        output = until(b"Run this setup and share this workspace?")
        assert b"guest can read and write" in output
        assert str(workspace).encode() in output
        if choice == "decline":
            os.write(master, b"n\n")
            until(b"Setup declined")
            assert process.wait(timeout=5) == 0
        else:
            process.send_signal(signal.SIGINT)
            assert process.wait(timeout=5) in (-signal.SIGINT, 130)
    assert (root / "policy.toml").read_bytes() == policy
    assert not (root / "agents").exists()
    assert not (root / "data/proxy-process.json").exists()
    assert not (root / "data/coord/nats/process.json").exists()


def test_missing_guest_retry_keeps_agent_setup_services_and_unrelated_traffic(tmp_path):
    policy = 'budget=12000\n[hosts]\n"*"={egress="allow",unknown_creds="allow"}\n'
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        instance.environment.update(PATH=f"{instance.root / 'bin'}:/usr/bin:/bin",
                                    TERM="xterm-256color", SAFEYOLO_NATS_TEST_INSTANCE=f"launch-{tmp_path.name}")
        arguments = ["coord", "start"]
        if binary := os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
            arguments += ["--binary", binary]
        started = instance.cli(*arguments)
        assert started.returncode == 0, started.stderr
        nats = json.loads(started.stdout)
        try:
            receipt = instance.root / "assets/guest/safeyolo-coord.sha256"
            missing = receipt.with_name("coord-checksum.fixture-missing")
            policy_before_setup = instance.policy.read_bytes()
            receipt.rename(missing)
            try:
                with terminal(instance, ["agent", "launch", str(workspace), "--name", "first", "--harness", "claude"]) as (process, master, until):
                    until(b"Run this setup and share this workspace?")
                    os.write(master, b"y\n")
                    until(b"Copy this selected host authentication and settings?")
                    os.write(master, b"n\n")
                    until(b"First-agent host setup failed", timeout=30)
                    assert process.wait(timeout=5) != 0
                assert instance.policy.read_bytes() == policy_before_setup
                assert instance.process.poll() is None
            finally:
                missing.rename(receipt)
            with terminal(instance, ["agent", "launch", str(workspace), "--name", "first"]) as (process, master, until):
                until(b"Run this setup and share this workspace?")
                os.write(master, b"y\n")
                until(b"Copy this selected host authentication and settings?")
                os.write(master, b"n\n")
                output = until(b"First-agent sandbox/harness startup failed", timeout=30)
                assert b"Preparing the shipped harness setup" in output
                assert process.wait(timeout=5) != 0
            policy_bytes = instance.policy.read_bytes()
            command = instance.root / "agents/first/home/.safeyolo-command"
            previous = command.stat()
            command_bytes = command.read_bytes()
            # The actual default selection finds the intended named agent.
            # It neither reapplies setup nor creates a second identity.
            with terminal(instance, ["agent", "launch", str(workspace), "--launcher", "tmux-window"]) as (process, _, until):
                output = until(b"First-agent sandbox/harness startup failed", timeout=30)
                assert b"Reusing agent first" in output
                assert b"Preparing the shipped harness setup" not in output
                assert process.wait(timeout=5) != 0
            assert instance.policy.read_bytes() == policy_bytes
            assert command.stat().st_ino == previous.st_ino and command.read_bytes() == command_bytes
            command.unlink()
            with terminal(instance, ["agent", "launch", str(workspace)]) as (process, master, until):
                output = until(b"Run this setup and share this workspace?")
                assert b"harness command is missing" in output
                os.write(master, b"y\n")
                until(b"Copy this selected host authentication and settings?")
                os.write(master, b"n\n")
                until(b"First-agent sandbox/harness startup failed", timeout=30)
                assert process.wait(timeout=5) != 0
            assert command.read_bytes() == command_bytes
            # Explicit repair uses the existing TOML writer. Whitespace can
            # change, while every saved policy choice and agent field stays.
            assert tomllib.loads(instance.policy.read_text()) == tomllib.loads(policy_bytes.decode())
            assert json.loads(instance.cli("coord", "status").stdout)["process"] == nats
            assert instance.process.poll() is None
            target = f"http://127.0.0.1:{origin.server_address[1]}/unrelated-agent"
            assert request(instance.paths["alice"], target)[0] == 200
            launcher_conflict = instance.cli("agent", "launch", str(workspace), "--name", "first", "--launcher", "tmux-pane")
            assert launcher_conflict.returncode != 0 and "different workspace, harness or launcher" in launcher_conflict.stderr
            other = tmp_path / "other-workspace"
            other.mkdir()
            conflict = instance.cli("agent", "launch", str(other), "--name", "first")
            assert conflict.returncode != 0 and "different workspace" in conflict.stderr
            assert tomllib.loads(instance.policy.read_text()) == tomllib.loads(policy_bytes.decode())
        finally:
            stopped = instance.cli("coord", "stop")
            assert stopped.returncode == 0, stopped.stderr
            assert json.loads(instance.cli("coord", "status").stdout)["state"] == "stopped"


CREDENTIAL_RETRY_POLICY = '''budget=12000
[hosts]
"*"={egress="allow",unknown_creds="prompt"}
[credential.synthetic]
match=["first-launch-key", "second-launch-key"]
headers=["authorization", "x-api-key"]
''' + AGENTS


@pytest.mark.parametrize("surface", ["approvals", "inspect"])
@pytest.mark.parametrize("window", ["list", "detail"])
@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_credential_retry_keeps_the_inspected_action(tmp_path, surface, window, decision):
    policy = CREDENTIAL_RETRY_POLICY
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/retry"
        headers = {"Authorization": "Bearer first-launch-key"}
        assert request(instance.paths["alice"], target, headers=headers)[0] == 428
        original = instance.admin("GET", "/admin/approvals")["approvals"][0]["request_id"]
        arguments = (["approvals", "review", "--agent", "alice"] if surface == "approvals"
                     else ["inspect", "--agent", "alice"])
        with terminal(instance, arguments) as (process, master, until):
            if surface == "inspect":
                until(b"inspect> ")
                os.write(master, b"review\n")
            output = until(b"Request number")
            if window == "detail":
                os.write(master, b"1\n")
                output += until(b"approve / reject")
            assert request(instance.paths["alice"], target, headers=headers)[0] == 428
            newest = instance.admin("GET", "/admin/approvals")["approvals"][0]["request_id"]
            assert newest != original
            shown = instance.cli("approvals", "show", original, "--agent", "alice", "--json")
            assert shown.returncode == 0, shown.stderr
            view = json.loads(shown.stdout)
            assert view["request_id"] == original and view["status"] == "pending"
            if window == "list":
                os.write(master, b"1\n")
                output += until(b"approve / reject")
            assert b"all agents in this instance, including future agents" in output
            os.write(master, decision.encode() + b"\n")
            output += until(b"No pending requests")
            if surface == "inspect":
                if b"inspect> " not in output:
                    until(b"inspect> ")
                os.write(master, b"quit\n")
            assert process.wait(timeout=5) == 0
            assert b"API 404 " not in output and b"first-launch-key" not in output
        assert origin.accepts == 0
        _wait_for_active_policy(instance)
        status, _, _ = request(instance.paths["alice"], target, headers=headers)
        assert status == (200 if decision == "approve" else 428)
        assert origin.accepts == (1 if decision == "approve" else 0)


@pytest.mark.parametrize("window", ["list", "detail"])
@pytest.mark.parametrize("change", ["other_agent", "fingerprint", "destination", "identity", "refusal", "resolution"])
def test_changed_credential_selection_refreshes_without_a_decision(tmp_path, window, change):
    policy = CREDENTIAL_RETRY_POLICY
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/stale"
        headers = {"Authorization": "Bearer first-launch-key"}
        assert request(instance.paths["alice"], target, headers=headers)[0] == 428
        identifier = instance.admin("GET", "/admin/approvals")["approvals"][0]["request_id"]
        view = json.loads(instance.cli("approvals", "show", identifier, "--json").stdout)
        with terminal(instance, ["approvals", "review", "--agent", "alice"]) as (process, master, until):
            until(b"Request number")
            if window == "detail":
                os.write(master, b"1\n")
                until(b"approve / reject")
            if change == "other_agent":
                assert request(instance.paths["bob"], target, headers=headers)[0] == 428
            elif change in ("fingerprint", "destination"):
                # Replace trusted fixture evidence to challenge the caller's
                # saved scope at both interaction windows. Real retries get new
                # request IDs; the separate controls exercise that producer.
                audit = instance.root / "logs/audit.jsonl"
                events = [json.loads(line) for line in audit.read_text().splitlines()]
                for event in events:
                    if event.get("event") == "security.credential_guard" and event.get("request_id") == identifier:
                        if change == "fingerprint":
                            event["approval"]["key"] = "hmac:changed-fixture"
                            event["details"]["fingerprint"] = "hmac:changed-fixture"
                        else:
                            event["host"] = event["approval"]["target"] = "localhost"
                audit.write_text("".join(json.dumps(event) + "\n" for event in events))
            elif change == "identity":
                instance.apply(policy.replace("ag-" + "a" * 32, "ag-" + "c" * 32))
            else:
                route = "deny" if change == "refusal" else "approve"
                credential = view["action"]["credentials"][0]
                instance.admin("POST", f"/admin/policy/baseline/{route}",
                               {"destination": "127.0.0.1", "cred_id": credential})
            before = instance.policy.read_bytes()
            audit = instance.root / "logs/audit.jsonl"
            before_events = [row for row in audit.read_text().splitlines() if '"admin.approval_added"' in row or '"admin.denial"' in row]
            os.write(master, b"1\n" if window == "list" else b"approve\n")
            marker = b"Request number" if change in ("fingerprint", "destination") else b"No pending requests"
            output = until(marker)
            assert b"API 404 " not in output and b"approve / reject" not in output
            if change in ("fingerprint", "destination"):
                os.write(master, b"\n")
            assert process.wait(timeout=5) == 0
            assert instance.policy.read_bytes() == before and origin.accepts == 0
            after_events = [row for row in audit.read_text().splitlines() if '"admin.approval_added"' in row or '"admin.denial"' in row]
            assert after_events == before_events
        if change not in ("fingerprint", "destination"):
            for decision in ("approve", "reject"):
                stale = instance.cli("approvals", decision, identifier, "--agent", "alice")
                assert stale.returncode != 0 and "API 404 " not in stale.stderr
        assert instance.policy.read_bytes() == before and origin.accepts == 0


@pytest.mark.parametrize("surface", ["direct", "inspect"])
@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_direct_credential_decision_keeps_the_selected_destination(tmp_path, decision, surface):
    policy = CREDENTIAL_RETRY_POLICY
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        port = origin.server_address[1]
        target = f"http://127.0.0.1:{port}/selected"
        changed = f"http://localhost:{port}/other-destination"
        headers = {"Authorization": "Bearer first-launch-key"}
        assert request(instance.paths["alice"], target, headers=headers)[0] == 428
        identifier = instance.admin("GET", "/admin/approvals")["approvals"][0]["request_id"]
        assert request(instance.paths["alice"], target, headers=headers)[0] == 428
        assert request(instance.paths["alice"], changed, headers=headers)[0] == 428
        if surface == "direct":
            result = instance.cli("approvals", decision, identifier, "--agent", "alice", "--json")
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)["status"] == ("approved" if decision == "approve" else "rejected")
        else:
            with terminal(instance, ["inspect", "--agent", "alice"]) as (process, master, until):
                until(b"inspect> ")
                os.write(master, f"approval {identifier}\n".encode())
                output = until(b"inspect> ")
                assert b"Status: pending" in output
                os.write(master, f"{decision} {identifier}\n".encode())
                output = until(b"inspect> ")
                expected = b"approved" if decision == "approve" else b"rejected"
                assert b"Status: " + expected in output
                os.write(master, b"quit\n")
                assert process.wait(timeout=5) == 0
        _wait_for_active_policy(instance)
        assert request(instance.paths["alice"], changed, headers=headers)[0] == 428
        assert origin.accepts == 0
        assert request(instance.paths["alice"], target, headers=headers)[0] == (200 if decision == "approve" else 428)


def test_credential_policy_write_rechecks_the_inspected_action(tmp_path):
    policy = CREDENTIAL_RETRY_POLICY
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/decision"
        assert request(instance.paths["alice"], target,
                       headers={"Authorization": "Bearer first-launch-key"})[0] == 428
        identifier = instance.admin("GET", "/admin/approvals")["approvals"][0]["request_id"]
        view = instance.admin("GET", f"/admin/approvals/{identifier}")
        action = view["action"]
        body = {"destination": action["host"], "cred_id": action["credentials"],
                "approval_request_id": identifier, "approval_action": action}
        before = instance.policy.read_bytes()
        for field, changed in (("host", "localhost"), ("agent_id", "ag-" + "c" * 32),
                               ("credentials", ["hmac:different"])):
            instance.admin("POST", "/admin/policy/baseline/approve",
                           {**body, "approval_action": {**action, field: changed}}, expected_status=409)
            assert instance.policy.read_bytes() == before
        instance.admin("POST", "/admin/policy/baseline/deny",
                       {"destination": action["host"], "cred_id": action["credentials"][0]})
        instance.admin("POST", "/admin/policy/baseline/approve", body, expected_status=409)
        assert instance.policy.read_bytes() == before and origin.accepts == 0
