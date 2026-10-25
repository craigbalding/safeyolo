"""First-launch host consent and the shared numbered operator interaction.

The proxy and policy effects are real. These controls do not claim a booted
guest or provider result; those require the authorized installed witness.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit

from tests.proxy_contracts.harness import request
from tests.proxy_contracts.scenarios import origin_server
from tests.proxy_contracts.test_native_coord_operator import terminal, wait_terminal_exit
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
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
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
@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_launch_refusal_has_no_setup_service_or_agent_effect(tmp_path, choice, harness):
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
    shutil.copy2(REPO / f"contrib/{harness}-host-setup.sh", scripts)
    instance = SimpleNamespace(root=root, environment={**os.environ, "TERM": "xterm-256color"})
    policy = (root / "policy.toml").read_bytes()
    # Keep the default Claude caller as well as explicit Codex selection.
    arguments = ["agent", "launch"] + (["--harness", harness] if harness == "codex" else [])
    with terminal(instance, arguments, cwd=workspace) as (process, master, until):
        output = until(b"Run this setup and share this workspace?")
        assert b"guest can read and write" in output
        assert str(workspace).encode() in output
        if choice == "decline":
            os.write(master, b"n\n")
            until(b"Setup declined")
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
        else:
            process.send_signal(signal.SIGINT)
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) in (-signal.SIGINT, 130)
    assert (root / "policy.toml").read_bytes() == policy
    assert not (root / "agents").exists()
    assert not (root / "data/proxy-process.json").exists()
    assert not (root / "data/coord/nats/process.json").exists()


@pytest.fixture
def codex_login_launch(tmp_path):
    """Exercise consent, identity and the real import without a guest/build lane."""
    artifacts, _, _ = native_inputs()
    binary = (artifacts / "safeyolo").resolve()
    root, workspace = tmp_path / "installed", tmp_path / "workspace"
    workspace.mkdir()
    initialized = subprocess.run([str(binary), "--root", str(root), "init"],
                                 capture_output=True, text=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(binary)
    scripts = root / "assets/contrib"
    scripts.mkdir(parents=True)
    # Setup's command payload is immaterial to this boundary. No services or
    # guest artifacts are installed, so successful selection must stop before
    # client startup at the real missing-proxy diagnostic.
    script = scripts / "codex-host-setup.sh"
    script.write_text('#!/bin/sh\nset -eu\n'
                      'mkdir -p "$SAFEYOLO_AGENT_HOME/.codex"\n'
                      'printf "#!/bin/sh\\nexit 0\\n" > "$SAFEYOLO_AGENT_HOME/.safeyolo-command"\n'
                      'chmod 700 "$SAFEYOLO_AGENT_HOME/.safeyolo-command"\n')
    script.chmod(0o700)
    host_codex = tmp_path / ".codex"
    host_codex.mkdir()
    login = host_codex / "auth.json"
    login.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {
        "access_token": "synthetic-first-launch-access", "refresh_token": "synthetic-first-launch-refresh",
    }}) + "\n")
    login.chmod(0o600)
    instance = SimpleNamespace(root=root, environment={**os.environ, "TERM": "xterm-256color",
                                                     "CODEX_HOME": str(host_codex)})
    instance.arguments = ["agent", "launch", str(workspace), "--name", "first", "--harness", "codex"]
    instance.login = login

    def cli(*args):
        result = subprocess.run([str(binary), "--root", str(root), *args],
                                env=instance.environment, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout) if result.stdout.startswith(("[", "{")) else result.stdout

    instance.cli = cli
    return instance


def _codex_choice(until, master, *, new=True):
    if new:
        until(b"Run this setup and share this workspace?")
        os.write(master, b"y\n")
    output = until(b"Codex login [a/h/file path")
    assert b"Agent files can be changed by the guest" in output
    assert b"Existing credential and network rules still apply" in output
    assert b"synthetic-first-launch-access" not in output
    assert b"synthetic-first-launch-refresh" not in output


@pytest.mark.parametrize("selection", ["host", "default_host", "file"])
def test_codex_launch_authorizes_selected_login_for_created_identity_before_startup(codex_login_launch, selection):
    instance = codex_login_launch
    if selection == "default_host":
        instance.environment.pop("CODEX_HOME")
        instance.environment["HOME"] = str(instance.login.parent.parent)
    original = instance.login.read_bytes(), instance.login.stat()
    with terminal(instance, instance.arguments) as (process, master, until):
        _codex_choice(until, master)
        assert instance.cli("credentials", "list") == []
        policy = (instance.root / "policy.toml").read_bytes()
        agent = tomllib.loads(policy.decode())["agents"]["first"]
        choice = str(instance.login) if selection == "file" else "h"
        os.write(master, choice.encode() + b"\n")
        output = until(b"Choose credential storage")
        assert not (instance.root / "data/credentials.key").exists()
        os.write(master, b"local\n")
        output += until(b"First-agent services failed")
        assert b"Codex login authorized for first" in output
        assert output.index(b"Codex login authorized") < output.index(b"Starting or reusing the installed services")
        assert b"synthetic-first-launch-access" not in output and b"synthetic-first-launch-refresh" not in output
        assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
    imported, = instance.cli("credentials", "list")
    assert imported["type"] == "codex_subscription"
    assert imported["codex"]["agent"] == "first"
    assert imported["codex"]["agent_id"] == agent["agent_id"]
    assert imported["codex"]["run_id"] is None
    home = instance.root / "agents/first/home"
    auth = home / ".codex/auth.json"
    marker = home / ".codex/.safeyolo-provenance.json"
    assert auth.read_bytes() == original[0] and auth.stat().st_mode & 0o777 == 0o600
    assert json.loads(marker.read_text())["state"] == "agent-local"
    assert instance.login.read_bytes() == original[0]
    assert instance.login.stat().st_ino == original[1].st_ino
    assert instance.login.stat().st_mode == original[1].st_mode
    assert (instance.root / "policy.toml").read_bytes() == policy
    saved = {path: path.read_bytes() for path in (auth, marker, instance.root / "data/credentials.enc")}
    # A stopped repeat does not silently import again or undo a revocation.
    for revoke in (False, True):
        if revoke:
            instance.cli("credentials", "remove", imported["name"])
        with terminal(instance, instance.arguments) as (process, master, until):
            _codex_choice(until, master, new=False)
            os.write(master, b"\n")
            output = until(b"First-agent services failed")
            assert b"Codex login authorized" not in output
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
        assert instance.cli("credentials", "list") == ([] if revoke else [imported])
        for path in (auth, marker):
            assert path.read_bytes() == saved[path]
        if not revoke:
            assert (instance.root / "data/credentials.enc").read_bytes() == saved[instance.root / "data/credentials.enc"]
    with terminal(instance, instance.arguments) as (process, master, until):
        _codex_choice(until, master, new=False)
        os.write(master, b"a\n")
        output = until(b"First-agent services failed")
        assert b"Codex login authorized for first" in output
        assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
    restored, = instance.cli("credentials", "list")
    assert restored["codex"]["agent_id"] == agent["agent_id"]
    assert restored["codex"]["import_id"] != imported["codex"]["import_id"]
    assert auth.read_bytes() == original[0]


def test_codex_launch_offers_passphrase_storage_on_its_first_import(codex_login_launch):
    instance = codex_login_launch
    protected = b"synthetic-codex-storage-passphrase"
    with terminal(instance, instance.arguments) as (process, master, until):
        _codex_choice(until, master)
        os.write(master, b"h\n")
        output = until(b"Choose credential storage")
        assert not (instance.root / "data/credentials.key").exists()
        os.write(master, b"passphrase\n")
        output += until(b"Storage passphrase:")
        os.write(master, protected + b"\n")
        output += until(b"Confirm storage passphrase:")
        os.write(master, protected + b"\n")
        output += until(b"First-agent services failed")
        assert b"Codex login authorized for first" in output
        assert protected not in output
        assert b"synthetic-first-launch-access" not in output
        assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
    assert (instance.root / "data/credentials.key").read_text() == "safeyolo-passphrase-v1"
    pass_file = instance.root.parent / "passphrase"
    pass_file.write_bytes(protected)
    imported, = instance.cli("credentials", "list", "--passphrase-file", str(pass_file))
    assert imported["codex"]["agent"] == "first"


def test_codex_login_selection_uses_the_launch_config(codex_login_launch):
    instance = codex_login_launch
    config = instance.root / "selected.toml"
    (instance.root / "config.toml").rename(config)
    binary = str(instance.root / "bin/safeyolo")
    with terminal(instance, command=[binary, "--config", str(config), *instance.arguments]) as (process, master, until):
        _codex_choice(until, master)
        os.write(master, b"h\n")
        until(b"Choose credential storage")
        os.write(master, b"local\n")
        output = until(b"First-agent services failed")
        assert b"Codex login authorized for first" in output
        assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
    result = subprocess.run([binary, "--config", str(config), "credentials", "list"],
                            env=instance.environment, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    record, = json.loads(result.stdout)
    agent = tomllib.loads((instance.root / "policy.toml").read_text())["agents"]["first"]
    assert record["codex"]["agent_id"] == agent["agent_id"]
    assert not (instance.root / "config.toml").exists()


@pytest.mark.parametrize("choice", ["skip", "cancel", "eof", "interrupt", "bad_input", "changed_identity"])
def test_codex_login_refusal_and_failed_selection_create_no_authority(codex_login_launch, choice):
    instance = codex_login_launch
    original = instance.login.read_bytes()
    with terminal(instance, instance.arguments) as (process, master, until):
        _codex_choice(until, master)
        if choice == "skip":
            os.write(master, b"\n")
            until(b"First-agent services failed")
        elif choice == "interrupt":
            process.send_signal(signal.SIGINT)
        elif choice == "eof":
            os.write(master, b"\x04")
            until(b"Launch cancelled")
        elif choice == "changed_identity":
            policy = instance.root / "policy.toml"
            document = tomlkit.parse(policy.read_text())
            document["agents"]["first"]["agent_id"] = "ag-" + "f" * 32
            policy.write_text(tomlkit.dumps(document))
            os.write(master, b"h\n")
            until(b"configuration identity changed")
        else:
            if choice == "bad_input":
                os.write(master, b"/no/such/login.json\n")
                output = until(b"Codex login [a/h/file path")
                assert b"cannot resolve selected Codex login input" in output
            os.write(master, b"q\n")
            until(b"Launch cancelled")
        code = wait_terminal_exit(process, master, bytearray(), timeout=5)
        if choice == "interrupt":
            assert code in (-signal.SIGINT, 130)
        elif choice in ("skip", "changed_identity"):
            assert code != 0
        else:
            assert code == 0
    assert instance.cli("credentials", "list") == []
    assert not (instance.root / "agents/first/home/.codex/auth.json").exists()
    assert instance.login.read_bytes() == original
    assert not (instance.root / "data/proxy-process.json").exists()
    assert not (instance.root / "data/coord/nats/process.json").exists()


@pytest.mark.parametrize("failure", ["malformed", "existing_login", "symlink", "directory"])
def test_codex_login_import_errors_preserve_owned_login_and_allow_cancellation(codex_login_launch, failure):
    instance = codex_login_launch
    with terminal(instance, instance.arguments) as (process, master, until):
        _codex_choice(until, master)
        auth = instance.root / "agents/first/home/.codex/auth.json"
        source = instance.login
        if failure == "malformed":
            source.write_text('{"tokens": "invalid-synthetic-login"}\n')
            diagnostic = b"invalid Codex login input"
        elif failure == "existing_login":
            auth.write_bytes(b"existing-agent-login\n")
            auth.chmod(0o600)
            diagnostic = b"selected agent already has Codex authentication"
        elif failure == "symlink":
            auth.symlink_to(source)
            diagnostic = b"unsafe agent-local path"
        else:
            source = instance.login.parent
            diagnostic = b"Codex authentication input must be a regular file"
        original = instance.login.read_bytes()
        os.write(master, ("a" if failure == "symlink" else str(source)).encode() + b"\n")
        output = until(b"Codex login [a/h/file path")
        assert diagnostic in output
        for secret in (b"synthetic-first-launch-access", b"synthetic-first-launch-refresh", b"invalid-synthetic-login"):
            assert secret not in output
        assert instance.cli("credentials", "list") == []
        os.write(master, b"q\n")
        until(b"Launch cancelled")
        assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
    assert instance.login.read_bytes() == original
    if failure == "malformed":
        # The selected copy remains for repair; adoption alone grants nothing.
        assert auth.read_bytes() == original
    elif failure == "existing_login":
        assert auth.read_bytes() == b"existing-agent-login\n"
    elif failure == "symlink":
        assert auth.is_symlink()
    else:
        assert not auth.exists()
    assert not (instance.root / "data/proxy-process.json").exists()


@pytest.mark.parametrize("missing_input", (
    ["rootfs-base.ext4", "Image", "initramfs.cpio.gz", "helper"]
    if os.uname().sysname == "Darwin" else ["rootfs-tree"]
))
@pytest.mark.parametrize("harness", ["claude", "codex"])
def test_missing_guest_retry_keeps_agent_setup_services_and_unrelated_traffic(missing_input, harness):
    policy = 'budget=12000\n[hosts]\n"*"={egress="allow",unknown_creds="allow"}\n'
    # Agent listeners use the installed root, not the fixture's separate proxy
    # socket directory. A normal Darwin pytest path can fail before boot entry.
    with tempfile.TemporaryDirectory(prefix="sy-first-", dir=Path.home()) as directory, \
            origin_server() as origin, native_instance(Path(directory), source=policy) as instance:
        tmp_path = Path(directory)
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        if os.uname().sysname == "Darwin":
            agent_socket = instance.root.resolve() / "data/sockets/10.200.0.1_first/proxy.sock"
            assert len(os.fsencode(agent_socket)) < 104, agent_socket
            # These bytes cannot boot a guest. The selected missing input (or
            # missing executable) must prevent any helper from being spawned.
            share = instance.root / "share"
            share.mkdir(exist_ok=True)
            for name in ("rootfs-base.ext4", "Image", "initramfs.cpio.gz"):
                if name != missing_input:
                    (share / name).write_bytes(b"prelaunch fixture, not a boot image\n")
            if missing_input == "helper":
                (instance.root / "bin/safeyolo-vm").unlink()
                diagnostic = b"No such file or directory (os error 2)"
            else:
                diagnostic = f"missing agent boot input: {share / missing_input}".encode()
        else:
            diagnostic = f"installed rootfs tree is missing: {instance.root / 'share/rootfs-tree'}".encode()
        instance.environment.update(PATH=f"{instance.root / 'bin'}:/usr/bin:/bin",
                                    TERM="xterm-256color", SAFEYOLO_NATS_TEST_INSTANCE=f"launch-{tmp_path.name}")
        arguments = ["coord", "start"]
        if binary := os.environ.get("SAFEYOLO_COORD_NATS_BINARY"):
            arguments += ["--binary", binary]
        started = instance.cli(*arguments)
        assert started.returncode == 0, started.stderr
        nats = json.loads(started.stdout)
        harness_args = ["--harness", harness] if harness == "codex" else []
        try:
            receipt = instance.root / "assets/guest/safeyolo-coord.sha256"
            missing = receipt.with_name("coord-checksum.fixture-missing")
            policy_before_setup = instance.policy.read_bytes()
            receipt.rename(missing)
            try:
                with terminal(instance, ["agent", "launch", str(workspace), "--name", "first", "--harness", harness]) as (process, master, until):
                    until(b"Run this setup and share this workspace?")
                    os.write(master, b"y\n")
                    if harness == "claude":
                        until(b"Copy this selected host authentication and settings?")
                        os.write(master, b"n\n")
                    until(b"First-agent host setup failed", timeout=30)
                    assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
                assert instance.policy.read_bytes() == policy_before_setup
                assert instance.process.poll() is None
            finally:
                missing.rename(receipt)
            with terminal(instance, ["agent", "launch", str(workspace), "--name", "first", *harness_args]) as (process, master, until):
                until(b"Run this setup and share this workspace?")
                os.write(master, b"y\n")
                if harness == "claude":
                    until(b"Copy this selected host authentication and settings?")
                    os.write(master, b"n\n")
                output = b""
                if harness == "codex":
                    output = until(b"Codex login [a/h/file path")
                    os.write(master, b"\n")
                output += until(b"First-agent sandbox/harness startup failed", timeout=30)
                assert b"Preparing the shipped harness setup" in output
                if harness == "codex":
                    assert b"Codex uses authentication and settings" in output
                    assert b"Copy this selected host authentication" not in output
                assert diagnostic in output, output
                assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
            runtime = instance.root / "agents/first/runtime.json"
            assert not runtime.exists()
            assert json.loads(instance.cli("agent", "status", "first").stdout)["runtime_state"] == "stopped"
            policy_bytes = instance.policy.read_bytes()
            command = instance.root / "agents/first/home/.safeyolo-command"
            previous = command.stat()
            command_bytes = command.read_bytes()
            home = command.parent
            if harness == "codex":
                # Boot staging wraps the generated command with the existing
                # guest observer; Codex remains the unchanged payload.
                payload = home / ".safeyolo-command.payload"
                assert payload.read_bytes() == (REPO / "contrib/codex-command.sh").read_bytes()
                config = home / ".codex/config.toml"
                document = tomlkit.parse(config.read_text())
                document["model"] = "operator-selected-model"
                config.write_text(tomlkit.dumps(document))
                auth = home / ".codex/auth.json"
                auth.write_text('{"synthetic": "selected-agent-login"}\n')
                auth.chmod(0o600)
                adopted = subprocess.run([str(instance.root / "bin/safeyolo-coord"), "codex-state", "--home", str(home), "adopt"],
                                         env=instance.environment, capture_output=True, text=True, timeout=15)
                assert adopted.returncode == 0, adopted.stderr
                selected_state = {path: path.read_bytes() for path in (config, auth, home / ".codex/.safeyolo-provenance.json")}
            # The actual default selection finds the intended named agent.
            # It neither reapplies setup nor creates a second identity.
            with terminal(instance, ["agent", "launch", str(workspace), "--launcher", "tmux-window", *harness_args]) as (process, master, until):
                output = b""
                if harness == "codex":
                    output = until(b"Codex login [a/h/file path")
                    os.write(master, b"\n")
                output += until(b"First-agent sandbox/harness startup failed", timeout=30)
                assert b"Reusing agent first" in output
                assert b"Preparing the shipped harness setup" not in output
                assert diagnostic in output, output
                assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
            assert not runtime.exists()
            assert instance.policy.read_bytes() == policy_bytes
            assert command.stat().st_ino == previous.st_ino and command.read_bytes() == command_bytes
            command.unlink()
            with terminal(instance, ["agent", "launch", str(workspace), *harness_args]) as (process, master, until):
                output = until(b"Run this setup and share this workspace?")
                assert b"harness command is missing" in output
                os.write(master, b"y\n")
                if harness == "claude":
                    until(b"Copy this selected host authentication and settings?")
                    os.write(master, b"n\n")
                if harness == "codex":
                    until(b"Codex login [a/h/file path")
                    os.write(master, b"\n")
                output = until(b"First-agent sandbox/harness startup failed", timeout=30)
                assert diagnostic in output, output
                assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
            assert not runtime.exists()
            assert command.read_bytes() == command_bytes
            if harness == "codex":
                assert {path: path.read_bytes() for path in selected_state} == selected_state
                assert payload.read_bytes() == (REPO / "contrib/codex-command.sh").read_bytes()
            # Explicit repair uses the existing TOML writer. Whitespace can
            # change, while every saved policy choice and agent field stays.
            assert tomllib.loads(instance.policy.read_text()) == tomllib.loads(policy_bytes.decode())
            assert json.loads(instance.cli("coord", "status").stdout)["process"] == nats
            assert instance.process.poll() is None
            target = f"http://127.0.0.1:{origin.server_address[1]}/unrelated-agent"
            assert request(instance.paths["alice"], target)[0] == 200
            launcher_conflict = instance.cli("agent", "launch", str(workspace), "--name", "first", "--launcher", "tmux-pane", *harness_args)
            assert launcher_conflict.returncode != 0 and "different workspace, harness or launcher" in launcher_conflict.stderr
            other = tmp_path / "other-workspace"
            other.mkdir()
            conflict = instance.cli("agent", "launch", str(other), "--name", "first", *harness_args)
            assert conflict.returncode != 0 and "different workspace" in conflict.stderr
            other_harness = "claude" if harness == "codex" else "codex"
            conflict = instance.cli("agent", "launch", str(workspace), "--name", "first", "--harness", other_harness)
            assert conflict.returncode != 0 and "different workspace, harness or launcher" in conflict.stderr
            assert tomllib.loads(instance.policy.read_text()) == tomllib.loads(policy_bytes.decode())
        finally:
            stopped = instance.cli("coord", "stop")
            assert stopped.returncode == 0, stopped.stderr
            assert json.loads(instance.cli("coord", "status").stdout)["state"] == "stopped"


def test_unsupported_launch_harness_is_rejected_before_instance_mutation(tmp_path):
    artifacts, _, _ = native_inputs()
    root = tmp_path / "installed"
    initialized = subprocess.run([str(artifacts / "safeyolo"), "--root", str(root), "init"],
                                 capture_output=True, text=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr
    saved = {name: (root / name).read_bytes() for name in ("policy.toml", "config.toml")}
    result = subprocess.run([str(artifacts / "safeyolo"), "--root", str(root), "agent", "launch", "--harness", "unknown"],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "available: claude, codex" in result.stderr
    assert {name: (root / name).read_bytes() for name in saved} == saved
    assert not (root / "agents").exists()
    assert not (root / "data/proxy-process.json").exists()
    assert not (root / "data/coord/nats/process.json").exists()


@pytest.mark.parametrize("auth_state", ["unadopted", "symlink"])
def test_codex_launch_keeps_selected_authentication_on_setup_refusal(tmp_path, auth_state):
    with native_instance(tmp_path) as instance:
        instance.environment.update(PATH=f"{instance.root / 'bin'}:/usr/bin:/bin", TERM="xterm-256color")
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        home = instance.root / "agents/first/home"
        codex = home / ".codex"
        codex.mkdir(parents=True, mode=0o700)
        config = codex / "config.toml"
        config.write_text('model = "operator-selected-model"\n')
        config.chmod(0o600)
        original_config = config.read_bytes()
        auth = codex / "auth.json"
        if auth_state == "symlink":
            target = tmp_path / "unrelated-auth"
            target.write_text("synthetic-unrelated-login\n")
            target.chmod(0o600)
            auth.symlink_to(target)
            diagnostic = b"unsafe agent-local path"
        else:
            auth.write_text("synthetic-unadopted-login\n")
            auth.chmod(0o600)
            diagnostic = b"codex-state adopt"
        original_auth = auth.read_bytes()
        policy = instance.policy.read_bytes()
        with terminal(instance, ["agent", "launch", str(workspace), "--name", "first", "--harness", "codex"]) as (process, master, until):
            until(b"Run this setup and share this workspace?")
            os.write(master, b"y\n")
            output = until(b"First-agent host setup failed", timeout=30)
            assert diagnostic in output
            assert original_auth not in output
            assert b"Copy this selected host authentication" not in output
            assert b"Starting or reusing the installed services" not in output
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) != 0
        assert instance.policy.read_bytes() == policy
        assert config.read_bytes() == original_config
        assert auth.read_bytes() == original_auth
        assert auth.is_symlink() == (auth_state == "symlink")
        if auth_state == "unadopted":
            assert json.loads((codex / ".safeyolo-provenance.json").read_text())["state"] == "legacy-unknown"
        assert not (instance.root / "data/coord/nats/process.json").exists()
        assert instance.process.poll() is None


CREDENTIAL_RETRY_POLICY = '''budget=12000
[hosts]
"*"={egress="allow",unknown_creds="prompt"}
[credential.synthetic]
match=["first-launch-key", "second-launch-key"]
headers=["authorization", "x-api-key"]
''' + AGENTS


def test_pending_credential_list_does_not_derive_authority_from_retained_audit(tmp_path):
    with origin_server() as origin, native_instance(tmp_path, source=CREDENTIAL_RETRY_POLICY) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/pending"
        assert request(instance.paths["alice"], target,
                       headers={"Authorization": "Bearer first-launch-key"})[0] == 428
        original = instance.admin("GET", "/admin/approvals")["approvals"][0]
        audit = instance.root / "logs/audit.jsonl"
        seed = next(row for row in map(json.loads, audit.read_text().splitlines())
                    if row.get("event") == "security.credential_guard")
        prompts = []
        for index in range(4000):
            fingerprint = f"hmac:{index:016x}"
            prompts.append({**seed, "request_id": f"req-{index:032x}",
                            "approval": {**seed["approval"], "key": fingerprint},
                            "details": {**seed["details"], "fingerprint": fingerprint}})
        # Duplicate and altered audit deliveries cannot create or replace
        # authority in the host-owned approval record.
        prompts.append({**prompts[0],
                        "approval": {**seed["approval"], "key": "hmac:second"},
                        "details": {**seed["details"], "fingerprint": "hmac:second"}})
        audit.write_text("".join(json.dumps(row) + "\n" for row in prompts))
        before = instance.policy.read_bytes()
        pending = instance.admin("GET", "/admin/approvals")["approvals"]
        listed = instance.cli("approvals", "list", "--agent", "alice", "--json")
        assert listed.returncode == 0, listed.stderr
        listed = json.loads(listed.stdout)["approvals"]
        assert [(row["request_id"], row["action"]) for row in listed] == [
            (row["request_id"], row["action"]) for row in pending]
        assert len(pending) == 1
        assert pending[0]["approval_id"] == original["approval_id"]
        assert pending[0]["action"] == original["action"]
        assert pending[0]["authority_digest"] == original["authority_digest"]
        assert instance.policy.read_bytes() == before and origin.accepts == 0


@pytest.mark.parametrize("surface", ["approvals", "inspect"])
@pytest.mark.parametrize("window", ["list", "detail"])
@pytest.mark.parametrize("decision", ["approve", "reject"])
def test_credential_retry_keeps_the_inspected_action(tmp_path, surface, window, decision):
    policy = CREDENTIAL_RETRY_POLICY
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/retry"
        headers = {"Authorization": "Bearer first-launch-key"}
        assert request(instance.paths["alice"], target, headers=headers)[0] == 428
        first = instance.admin("GET", "/admin/approvals")["approvals"][0]
        original = first["approval_id"]
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
            newest = instance.admin("GET", "/admin/approvals")["approvals"][0]
            assert newest["approval_id"] == original
            assert newest["action"] == first["action"]
            shown = instance.cli("approvals", "show", original, "--agent", "alice", "--json")
            assert shown.returncode == 0, shown.stderr
            view = json.loads(shown.stdout)
            assert view["approval_id"] == original and view["status"] == "pending"
            assert view["request_id"] == first["request_id"]
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
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
            assert b"API 404 " not in output and b"first-launch-key" not in output
        assert origin.accepts == 0
        _wait_for_active_policy(instance)
        status, _, _ = request(instance.paths["alice"], target, headers=headers)
        assert status == (200 if decision == "approve" else 428)
        assert origin.accepts == (1 if decision == "approve" else 0)


@pytest.mark.parametrize("window", ["list", "detail"])
@pytest.mark.parametrize("change", ["other_agent", "fingerprint", "destination", "identity", "refusal", "policy_allow"])
def test_credential_selection_retains_its_authority_and_rechecks_policy(tmp_path, window, change):
    policy = CREDENTIAL_RETRY_POLICY
    with origin_server() as origin, native_instance(tmp_path, source=policy) as instance:
        target = f"http://127.0.0.1:{origin.server_address[1]}/stale"
        headers = {"Authorization": "Bearer first-launch-key"}
        assert request(instance.paths["alice"], target, headers=headers)[0] == 428
        identifier = instance.admin("GET", "/admin/approvals")["approvals"][0]["approval_id"]
        view = json.loads(instance.cli("approvals", "show", identifier, "--json").stdout)
        with terminal(instance, ["approvals", "review", "--agent", "alice"]) as (process, master, until):
            until(b"Request number")
            if window == "detail":
                os.write(master, b"1\n")
                until(b"approve / reject")
            if change == "other_agent":
                assert request(instance.paths["bob"], target, headers=headers)[0] == 428
            elif change in ("fingerprint", "destination"):
                changed_target = target.replace("127.0.0.1", "localhost") if change == "destination" else target
                changed_headers = {"Authorization": "Bearer second-launch-key"} if change == "fingerprint" else headers
                assert request(instance.paths["alice"], changed_target, headers=changed_headers)[0] == 428
            elif change == "identity":
                instance.apply(policy.replace("ag-" + "a" * 32, "ag-" + "c" * 32))
            elif change == "refusal":
                instance.admin("POST", f"/admin/approvals/{identifier}", {"decision": "reject"})
            else:
                credential = view["action"]["credentials"][0]
                instance.admin("POST", "/admin/policy/baseline/approve",
                               {"destination": "127.0.0.1", "cred_id": credential})
            before = instance.policy.read_bytes()
            audit = instance.root / "logs/audit.jsonl"
            before_events = [row for row in audit.read_text().splitlines() if '"admin.approval_added"' in row or '"admin.denial"' in row]
            if change in ("other_agent", "fingerprint", "destination"):
                current = instance.admin("GET", f"/admin/approvals/{identifier}")
                assert current["status"] == "pending" and current["action"] == view["action"]
                assert current["authority_digest"] == view["authority_digest"]
                pending = instance.admin("GET", "/admin/approvals")["approvals"]
                assert len({row["approval_id"] for row in pending}) == 2
                if window == "list":
                    os.write(master, b"1\n")
                    until(b"approve / reject")
                os.write(master, b"approve\n")
                until(b"No pending requests")
                assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
                approved = instance.admin("GET", f"/admin/approvals/{identifier}")
                assert approved["status"] == "approved" and approved["action"] == view["action"]
                assert origin.accepts == 0
                assert request(instance.paths["alice"], target, headers=headers)[0] == 200
                if change == "other_agent":
                    assert request(instance.paths["bob"], target, headers=headers)[0] == 200
                else:
                    assert request(instance.paths["alice"], changed_target, headers=changed_headers)[0] == 428
                return
            os.write(master, b"1\n" if window == "list" else b"approve\n")
            output = until(b"No pending requests")
            assert b"API 404 " not in output and b"approve / reject" not in output
            assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
            assert instance.policy.read_bytes() == before and origin.accepts == 0
            after_events = [row for row in audit.read_text().splitlines() if '"admin.approval_added"' in row or '"admin.denial"' in row]
            assert after_events == before_events
        for decision in ("approve", "reject"):
            stale = instance.cli("approvals", decision, identifier, "--agent", "alice", "--json")
            if change == "identity":
                assert stale.returncode != 0 and "selected current agent" in stale.stderr
            elif change == "policy_allow":
                assert stale.returncode != 0 and "superseded" in stale.stderr
                assert instance.admin("GET", f"/admin/approvals/{identifier}")["status"] == "superseded"
            else:
                assert stale.returncode == 0, stale.stderr
                assert json.loads(stale.stdout)["status"] == "rejected"
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
                assert wait_terminal_exit(process, master, bytearray(), timeout=5) == 0
        _wait_for_active_policy(instance)
        assert request(instance.paths["alice"], changed, headers=headers)[0] == 428
        assert origin.accepts == 0
        assert request(instance.paths["alice"], target, headers=headers)[0] == (200 if decision == "approve" else 428)


def test_credential_policy_write_cannot_bypass_canonical_approval(tmp_path):
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
                           {**body, "approval_action": {**action, field: changed}}, expected_status=503)
            assert instance.policy.read_bytes() == before
        instance.admin("POST", "/admin/policy/baseline/approve", body, expected_status=503)
        assert instance.policy.read_bytes() == before
        instance.admin("POST", "/admin/policy/baseline/deny",
                       {"destination": action["host"], "cred_id": action["credentials"][0]})
        # The old denial endpoint only logs. Audit alone cannot decide the
        # canonical record; the shared resolver records the actual refusal.
        assert instance.admin("GET", f"/admin/approvals/{view['approval_id']}")["status"] == "pending"
        instance.admin("POST", f"/admin/approvals/{view['approval_id']}", {"decision": "reject"})
        instance.admin("POST", "/admin/policy/baseline/approve", body, expected_status=503)
        replay = instance.admin("POST", f"/admin/approvals/{view['approval_id']}",
                                {"decision": "approve", "option": "persistent"})
        assert replay["status"] == "rejected"
        assert instance.policy.read_bytes() == before and origin.accepts == 0
