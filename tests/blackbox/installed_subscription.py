"""Compose explicit subscription adoption with the owned two-guest journey.

Reuse its verified installed identity, controlled TLS provider and proxy restart.
No paid provider, coding model, replacement runtime or copied host login is used.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import uuid
from pathlib import Path

import tomlkit

if __package__:
    from .guest_exec import guest_command_args
    from .installed_lifecycle import checked
else:
    from guest_exec import guest_command_args
    from installed_lifecycle import checked


class SubscriptionJourney:
    """Keep one synthetic import across the pair's actual proxy replacement."""

    def __init__(self, cli: str, root: Path, owner: str, peer: str, sinkhole):
        self.cli, self.root, self.owner, self.peer, self.sinkhole = cli, root, owner, peer, sinkhole
        self.report: list[dict] = []
        self.nonce = uuid.uuid4().hex
        self.name = "bb-owned-subscription"
        self.created_logins: list[Path] = []
        self.imported = False

    def login(self, agent: str) -> Path:
        return self.root / "agents" / agent / "home/.codex/bb-subscription.json"

    def invoke(self, agent: str, operation: str, allowed: bool) -> None:
        marker = "bbsubscription-" + uuid.uuid4().hex
        before = self.sinkhole.get_requests()
        prior_tokens = json.loads(self.login(agent).read_text())["tokens"]
        command = shlex.join(["python3", "/workspace/tests/blackbox/isolation/installed_subscription.py", operation, marker])
        result = checked(guest_command_args(self.cli, agent, command), timeout=30)
        lines = [line.removeprefix("SUBSCRIPTION=") for line in result.stdout.splitlines() if line.startswith("SUBSCRIPTION=")]
        assert len(lines) == 1, "subscription guest observation missing"
        observation = json.loads(lines[0])
        after = self.sinkhole.get_requests()
        delivered = after[len(before):]
        # Retain sanitized reached effects before any assertion can fail.
        value = {"agent": agent, "guest": observation,
                 "provider": [{"host": row.host, "method": row.method, "path": row.path,
                               "body_sha256": hashlib.sha256(row.body_bytes).hexdigest(),
                               "authorization_sha256": hashlib.sha256(next((value for name, value in row.headers.items()
                                   if name.lower() == "authorization"), "").encode()).hexdigest()}
                              for row in delivered]}
        self.report.append(value)
        assert len(after) >= len(before), "provider history was reset during the subscription operation"
        assert observation["status"] == (200 if allowed else 428), value
        assert len(delivered) == int(allowed), value
        if not allowed:
            return
        row = delivered[0]
        assert row.method == "POST" and any(name.lower() == "x-probe-marker" and value == marker
                                             for name, value in row.headers.items()), value
        if operation == "access":
            assert row.host == "chatgpt.com" and row.path == "/backend-api/codex/responses", value
            assert any(name.lower() == "authorization" and value == "Bearer " + prior_tokens["access_token"]
                       for name, value in row.headers.items()), "provider did not receive the exact adopted access token"
        else:
            assert row.host == "auth.openai.com" and row.path == "/oauth/token", value
            assert json.loads(row.body)["refresh_token"] == prior_tokens["refresh_token"], "provider received a different refresh token"
            tokens = json.loads(self.login(agent).read_text())["tokens"]
            assert tokens["access_token"] != prior_tokens["access_token"] and tokens["refresh_token"] != prior_tokens["refresh_token"]
            assert observation["token_fingerprints"] == {key: hashlib.sha256(value.encode()).hexdigest()
                                                        for key, value in tokens.items()}

    def prepare(self) -> None:
        """Show that provisioned files do not grant authority; explicitly adopt."""
        policy_path = self.root / "policy.toml"
        policy = tomlkit.parse(policy_path.read_text())
        for host in ("auth.openai.com", "chatgpt.com"):
            policy["hosts"][host] = {"egress": "allow", "unknown_creds": "prompt"}
        candidate = self.root / "bb-subscription-policy.toml"
        with candidate.open("x") as output:
            output.write(tomlkit.dumps(policy))
        try:
            checked([self.cli, "--root", str(self.root), "policy", "apply", str(candidate)])
        finally:
            candidate.unlink()
        login = {"auth_mode": "chatgpt", "tokens": {
            "access_token": f"bbsubscription-access-{self.nonce}-0",
            "refresh_token": f"bbsubscription-refresh-{self.nonce}-0"}}
        for agent in (self.owner, self.peer):
            path = self.login(agent)
            assert not path.exists(), "subscription fixture would replace existing client credentials"
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps(login))
            self.created_logins.append(path)
            path.chmod(0o600)
            # Preserve a host copy for explicit import; guest/client renewal
            # changes its own file and must not alter the selected input.
        selected = self.root / "bb-subscription-host-login.json"
        with selected.open("x") as output:
            output.write(json.dumps(login))
        selected.chmod(0o600)
        try:
            self.invoke(self.owner, "access", False)
            self.invoke(self.peer, "access", False)
            result = checked([self.cli, "--root", str(self.root), "credentials", "import-codex", self.name,
                              "--storage", "local", "--agent", self.owner, "--auth-file", str(selected), "--scope", "run"])
            self.imported = True
            assert not any(value in result.stdout for value in login["tokens"].values()), "host import exposed a token"
        finally:
            selected.unlink()
        self.invoke(self.owner, "access", True)
        self.invoke(self.owner, "refresh", True)
        self.invoke(self.owner, "access", True)
        self.invoke(self.peer, "refresh", False)
        self.invoke(self.peer, "access", False)

    def after_restart(self) -> None:
        """Retain renewal recognition, refuse another guest, then revoke."""
        self.invoke(self.owner, "access", True)
        self.invoke(self.owner, "refresh", True)
        self.invoke(self.owner, "access", True)
        self.login(self.peer).write_bytes(self.login(self.owner).read_bytes())
        self.invoke(self.peer, "access", False)
        self.invoke(self.peer, "refresh", False)
        checked([self.cli, "--root", str(self.root), "credentials", "remove", self.name])
        self.imported = False
        self.invoke(self.owner, "access", False)
        self.invoke(self.owner, "refresh", False)

    def cleanup(self) -> None:
        if self.imported:
            checked([self.cli, "--root", str(self.root), "credentials", "remove", self.name])
            self.imported = False
        for path in self.created_logins:
            path.unlink(missing_ok=True)
