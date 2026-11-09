"""Guided native authentication owners, without claiming provider-backed use.

The real host setup, encrypted store, active grant and Agent API run here.
Real Codex/Claude inference remains separate installed acceptance.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tomllib

import pytest

from tests.proxy_contracts.test_native_credentials_cli import restart
from tests.proxy_contracts.test_native_policy_cli import DENY, native_instance

AGENTS = '''
[agents.alice]
agent_id="ag-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
[agents.bob]
agent_id="ag-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''


@pytest.mark.parametrize("client", ["codex", "claude"])
def test_guided_owners_preserve_custody_denies_and_separate_readiness(tmp_path, client):
    service = {
        "schema_version": 1, "name": client,
        "default_host": "chatgpt.com" if client == "codex" else "api.anthropic.com",
        "auth": {"type": "bearer"},
        "capabilities": {"inference": {"routes": [{"methods": ["POST"], "path": "/**"}]}},
    }
    with native_instance(tmp_path, source=DENY + AGENTS, services=True,
                         service_sources={f"{client}.yaml": json.dumps(service)}) as instance:
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
                       "/bin/sh", "-c", "test -n \"$SAFEYOLO_CODEX_GATEWAY_TOKEN\" && printf CLIENT_STARTED"]
            launched = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
            assert launched.returncode == 0 and launched.stdout == "CLIENT_STARTED"
            assert instance.cli("services", "revoke", "alice", client).returncode == 0
            denied = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=20)
            assert denied.returncode != 0 and denied.stdout == ""
            assert "sgw_" not in launched.stdout + launched.stderr + denied.stdout + denied.stderr
