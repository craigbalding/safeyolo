"""Guided native authentication owners, without claiming provider-backed use.

The real host setup, encrypted store, active grant and Agent API run here.
Real Codex/Claude inference remains separate installed acceptance.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import tomllib
from contextlib import contextmanager
from pathlib import Path

import pytest

from tests.proxy_contracts.harness import child_process, wait_ready
from tests.proxy_contracts.test_native_credentials_cli import restart
from tests.proxy_contracts.test_native_policy_cli import DENY, NativeInstance, native_inputs

AGENTS = '''
[agents.alice]
agent_id="ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[agents.bob]
agent_id="ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''


@contextmanager
def authentication_instance(directory, client, service):
    """Run the actual auth owners without packaging unrelated VM/runtime inputs."""
    artifacts, _, _ = native_inputs()
    root = directory / "instance"
    initialized = subprocess.run([str(artifacts / "safeyolo"), "--root", str(root), "init"],
                                 capture_output=True, text=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr
    (root / "policy.toml").write_text(DENY + AGENTS)
    (root / "bin").mkdir()
    for name in ("safeyolo", "safeyolo-coord", "safeyolo-proxy"):
        (root / "bin" / name).symlink_to((artifacts / name).resolve())
    repository = Path(__file__).resolve().parents[2]
    assets = root / "assets"
    assets.mkdir()
    for name in ("contrib", "docs", "repo-map.toml"):
        (assets / name).symlink_to(repository / name)
    (assets / "skills").symlink_to(repository / "cli/src/safeyolo/agent_context/skills")
    guest = assets / "guest/safeyolo-coord"
    guest.parent.mkdir()
    # This Linux-only owner control can reuse the native Linux adapter. The
    # checked staging owner still validates its ELF architecture, identity/hash.
    shutil.copy2(artifacts / "safeyolo-coord", guest)
    guest.with_suffix(".version").write_text(subprocess.check_output(
        [str(artifacts / "safeyolo-coord"), "--version"], text=True))
    with guest.open("rb") as source:
        guest.with_suffix(".sha256").write_text(hashlib.file_digest(source, "sha256").hexdigest() + "\n")
    (root / "builtin-services").mkdir(exist_ok=True)
    (root / "services").mkdir(exist_ok=True)
    (root / "services" / f"{client}.yaml").write_text(json.dumps(service))
    try:
        with tempfile.TemporaryDirectory(prefix="sy-auth-") as sockets:
            paths = {name: str(Path(sockets) / f"{name}.sock") for name in ("alice", "bob")}
            config = ('admin_port=0\nflow_store_enabled=false\nagent_api_enabled=true\n'
                      'gateway_builtin_services_dir="builtin-services"\ngateway_services_dir="services"\n')
            for index, (name, path) in enumerate(paths.items(), 2):
                config += (f'[[listeners]]\nagent_id="{name}"\nsocket_path={json.dumps(path)}\n'
                           f'source_id="10.0.0.{index}"\n')
            (root / "config.toml").write_text(config)
            environment = dict(os.environ, SAFEYOLO_CONFIG_DIR=str(root),
                               SAFEYOLO_NATIVE_CONFIG_PATH=str(root / "config.toml"))
            with child_process([str(root / "bin/safeyolo-proxy"), "--config", str(root / "config.toml")],
                               root, environment) as process:
                ready = root / "data/ready.json"
                wait_ready(process, [ready, *map(Path, paths.values())], root / "process.log",
                           readiness_file=ready, expected_backend="rust-m2")
                yield NativeInstance(root, process, paths, environment)
    finally:
        guest.unlink()
        for staged in (root / "agents").glob("*/home/.safeyolo/safeyolo-coord"):
            staged.unlink()


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_guided_owners_preserve_custody_denies_and_separate_readiness(tmp_path, client):
    service = {
        "schema_version": 1, "name": client,
        "default_host": "chatgpt.com" if client == "codex" else "api.anthropic.com",
        "auth": {"type": "bearer"},
        "capabilities": {"inference": {"routes": [{"methods": ["POST"], "path": "/**"}]}},
    }
    with authentication_instance(tmp_path, client, service) as instance:
        operator = tmp_path / "operator"
        workspace = tmp_path / "workspace"
        operator.mkdir()
        workspace.mkdir()
        instance.environment.update(HOME=str(operator), PATH=f"{instance.root / 'bin'}:/usr/bin:/bin",
                                    SAFEYOLO_CLAUDE_COPY_HOST_STATE="0")
        script = instance.root / "assets/contrib" / f"{client}-host-setup.sh"
        configured = instance.cli("agent", "configure", "alice", "--workspace", str(workspace),
                                  "--host-script", str(script))
        assert configured.returncode == 0, configured.stderr
        home = instance.root / "agents/alice/home"
        directory = home / f".{client}"
        guest_auth = directory / ("auth.json" if client == "codex" else ".credentials.json")
        guest_auth.write_text("retained-guest-authentication")
        guest_auth.chmod(0o600)
        if client == "claude":
            (directory / "settings.json").write_text(json.dumps({
                "permissions": {"deny": ["Bash(retain-this-deny)"]}, "env": {"UNRELATED": "retained"},
            }))
        source = operator / "host-login.json"
        payload = base64.urlsafe_b64encode(b'{"exp":2000000000}').decode().rstrip("=")
        access = f"header.{payload}.signature" if client == "codex" else "synthetic-guided-access"
        login = {"auth_mode": "chatgpt", "tokens": {
            "access_token": access, "refresh_token": "synthetic-guided-refresh", "account_id": "selected-account",
        }} if client == "codex" else {"claudeAiOauth": {
            "accessToken": access, "refreshToken": "synthetic-guided-refresh",
            "expiresAt": 2000000000000, "scopes": ["user:profile", "user:inference"],
        }}
        source.write_text(json.dumps(login))
        original = source.read_bytes()
        passphrase = operator / "passphrase"
        passphrase.write_text("synthetic-guided-passphrase")
        storage = ["--storage", "local"] if client == "codex" else [
            "--storage", "passphrase", "--passphrase-file", str(passphrase),
        ]
        arguments = ["agent", "auth", "alice", "--authentication", "host-vault", "--credential", "selected",
                     "--auth-file", str(source), "--authorize", "--json", *storage]
        refused = instance.cli(*arguments)
        assert refused.returncode != 0
        assert "retained" in json.loads(refused.stdout)["error"]
        assert guest_auth.read_text() == "retained-guest-authentication"
        assert not (instance.root / "data/credentials.enc").exists()
        accepted = instance.cli(*arguments, "--remove-guest-auth", timeout=30)
        assert accepted.returncode == 0, accepted.stderr
        report = json.loads(accepted.stdout)
        assert report["configuration"] == "host-vault"
        assert report["authorization"]["binding"]["credential"] == "selected"
        assert report["vault"]["availability"] == "available"
        assert report["selected_account"]["subscription_client"] == client
        assert report["provider_validity"] == "unknown" and report["client_use"] == "not_observed"
        assert not guest_auth.exists() and source.read_bytes() == original
        assert tomllib.loads(instance.policy.read_text())["hosts"]["*"]["egress"] == "deny"
        if client == "claude":
            settings = json.loads((directory / "settings.json").read_text())
            assert settings["permissions"]["deny"] == ["Bash(retain-this-deny)"]
            assert settings["env"]["UNRELATED"] == "retained"
        else:
            assert report["selected_account"]["chatgpt_account_id"] == "selected-account"
        encrypted = (instance.root / "data/credentials.enc").read_bytes()
        repeated = instance.cli("agent", "auth", "alice", "--authentication", "host-vault",
                                "--credential", "selected", "--authorize", "--json", timeout=30)
        assert repeated.returncode == 0, repeated.stderr
        assert (instance.root / "data/credentials.enc").read_bytes() == encrypted
        for result in [refused, accepted, repeated]:
            for secret in [access, "synthetic-guided-refresh", "synthetic-guided-passphrase"]:
                assert secret not in result.stdout + result.stderr
            assert "sgw_" not in result.stdout
        if client == "claude":
            assert instance.cli("credentials", "lock").returncode == 0
            locked = json.loads(instance.cli("agent", "auth", "alice", "--json").stdout)
            assert locked["configuration"] == "host-vault" and locked["vault"]["availability"] == "locked"
            assert locked["authorization"]["state"] == "configured"
            assert locked["selected_account"] is None
            assert instance.cli("credentials", "unlock", "--passphrase-file", str(passphrase)).returncode == 0
            with restart(instance) as restarted:
                after = json.loads(restarted.cli("agent", "auth", "alice", "--json").stdout)
                assert after["vault"]["availability"] == "locked"
                assert after["configuration"] == "host-vault"
                assert after["authorization"]["binding"]["credential"] == "selected"
        else:
            # The actual guest entry reads the active gateway grant and refuses
            # revoked access before starting its command. No model is invoked.
            environment = {**os.environ, "HOME": str(home), "SAFEYOLO_COORD_SOCKET": instance.paths["alice"],
                           "SAFEYOLO_COORD_TOKEN_PATH": str(instance.root / "data/agent_token")}
            command = [str(home / ".safeyolo/safeyolo-coord"), "client-exec", client, "--",
                       "/bin/sh", "-c", 'test -n "$SAFEYOLO_CODEX_GATEWAY_TOKEN" && '
                       'printf %s "$SAFEYOLO_CODEX_GATEWAY_TOKEN" | sha256sum']
            launched = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
            assert launched.returncode == 0 and len(launched.stdout.split()[0]) == 64
            with restart(instance) as restarted:
                relaunched = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
                assert relaunched.returncode == 0 and len(relaunched.stdout.split()[0]) == 64
                assert relaunched.stdout != launched.stdout
                assert restarted.cli("services", "revoke", "alice", client).returncode == 0
                denied = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
                assert denied.returncode != 0 and denied.stdout == ""
            assert "sgw_" not in "".join(result.stdout + result.stderr for result in (launched, relaunched, denied))
