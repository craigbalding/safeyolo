"""Tests for agent authorize and revoke commands."""

from pathlib import Path

import pytest
import typer
import yaml
from typer.testing import CliRunner

from safeyolo.agents_store import load_agent, save_agent
from safeyolo.commands.agent import _parse_mount, _validate_instance_name
from safeyolo.commands.mount import is_path_protected

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_service(config_dir: Path, name: str, capabilities: dict, default_host: str = "", auth: dict | None = None) -> None:
    """Write a v1 schema service YAML into the user services dir."""
    services_dir = config_dir / "services"
    services_dir.mkdir(exist_ok=True)
    svc = {"schema_version": 1, "name": name, "capabilities": capabilities}
    if default_host:
        svc["default_host"] = default_host
    if auth:
        svc["auth"] = auth
    else:
        svc["auth"] = {"type": "bearer"}
    (services_dir / f"{name}.yaml").write_text(yaml.dump(svc, sort_keys=False))


def _write_policy(config_dir: Path, hosts: dict | None = None) -> None:
    """Update policy.toml with optional hosts section."""
    import tomlkit

    policy_path = config_dir / "policy.toml"
    if policy_path.exists():
        doc = tomlkit.parse(policy_path.read_text())
    else:
        doc = tomlkit.document()
        doc.add("version", "2.0")

    if hosts is not None:
        if "hosts" in doc:
            del doc["hosts"]
        hosts_table = tomlkit.table()
        for host, config in hosts.items():
            if config is None:
                hosts_table.add(host, tomlkit.table())
            elif isinstance(config, dict):
                it = tomlkit.inline_table()
                for k, v in config.items():
                    it.append(k, v)
                hosts_table.add(host, it)
            else:
                hosts_table.add(host, config)
        doc.add("hosts", hosts_table)

    policy_path.write_text(tomlkit.dumps(doc))


def _create_agent(config_dir: Path, name: str, extra: dict | None = None) -> None:
    """Save minimal agent metadata."""
    meta = {"folder": "/tmp/proj"}
    if extra:
        meta.update(extra)
    save_agent(name, meta)


def _store_vault_cred(config_dir: Path, name: str, cred_type: str = "bearer", value: str = "secret") -> None:
    """Store a credential in the vault for testing."""
    from safeyolo.commands.vault import _load_vault

    vault, VaultCredential = _load_vault()
    vault.store(VaultCredential(name=name, type=cred_type, value=value))


def _invoke(cli_runner: CliRunner, args: list[str], input_text: str | None = None):
    """Invoke the agent CLI command."""
    from safeyolo.commands.agent import agent_app

    return cli_runner.invoke(agent_app, args, input=input_text)


# ---------------------------------------------------------------------------
# Service resolution
# ---------------------------------------------------------------------------


class TestServiceResolution:
    def test_unknown_service_rejected(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        result = _invoke(cli_runner, ["authorize", "boris", "nonexistent", "--token", "x"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_builtin_service_resolved(self, cli_runner, tmp_config_dir):
        """A service in the user services dir is found."""
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "testsvc",
            {"reader": {"description": "Read-only", "routes": []}},
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "testsvc",
                "--capability",
                "reader",
                "--token",
                "tok123",
            ],
        )
        assert result.exit_code == 0
        assert "Authorized" in result.output


# ---------------------------------------------------------------------------
# Capability selection
# ---------------------------------------------------------------------------


class TestCapabilitySelection:
    def test_single_capability_auto_selected(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "onerole",
            {"only": {"description": "Only capability", "routes": []}},
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "onerole",
                "--token",
                "x",
            ],
        )
        assert result.exit_code == 0
        assert "Auto-selected capability" in result.output
        agent = load_agent("boris")
        assert agent["services"]["onerole"]["capability"] == "only"

    def test_capability_flag_works(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "multi",
            {
                "reader": {"description": "Read", "routes": []},
                "writer": {"description": "Write", "routes": []},
            },
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "multi",
                "--capability",
                "writer",
                "--token",
                "x",
            ],
        )
        assert result.exit_code == 0
        agent = load_agent("boris")
        assert agent["services"]["multi"]["capability"] == "writer"

    def test_invalid_capability_rejected(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "multi",
            {
                "reader": {"description": "Read", "routes": []},
                "writer": {"description": "Write", "routes": []},
            },
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "multi",
                "--capability",
                "admin",
                "--token",
                "x",
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output.lower()


# ---------------------------------------------------------------------------
# Credential flow
# ---------------------------------------------------------------------------


class TestCredentialFlow:
    def test_token_stores_in_vault(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
            auth={"type": "api_key"},
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "my-secret",
            ],
        )
        assert result.exit_code == 0
        assert "Stored credential" in result.output

        # Verify vault has it
        from safeyolo.commands.vault import _load_vault

        vault, _ = _load_vault()
        cred = vault.get("svc-cred")
        assert cred is not None
        assert cred.value == "my-secret"
        assert cred.type == "api_key"

    def test_token_file_reads_and_stores(self, cli_runner, tmp_config_dir, tmp_path):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )
        token_file = tmp_path / "token.txt"
        token_file.write_text("file-secret\n")
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token-file",
                str(token_file),
            ],
        )
        assert result.exit_code == 0

        from safeyolo.commands.vault import _load_vault

        vault, _ = _load_vault()
        cred = vault.get("svc-cred")
        assert cred is not None
        assert cred.value == "file-secret"

    def test_token_env_reads_and_stores(self, cli_runner, tmp_config_dir, monkeypatch):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )
        monkeypatch.setenv("MY_TOKEN", "env-secret")
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token-env",
                "MY_TOKEN",
            ],
        )
        assert result.exit_code == 0

        from safeyolo.commands.vault import _load_vault

        vault, _ = _load_vault()
        cred = vault.get("svc-cred")
        assert cred is not None
        assert cred.value == "env-secret"

    def test_credential_name_reuses_existing(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )
        _store_vault_cred(tmp_config_dir, "my-existing-cred")
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--credential-name",
                "my-existing-cred",
            ],
        )
        assert result.exit_code == 0
        agent = load_agent("boris")
        assert agent["services"]["svc"]["token"] == "my-existing-cred"

    def test_missing_credential_name_rejected(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--credential-name",
                "ghost",
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_auto_name_increments(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )
        # Store first credential with the base name
        _store_vault_cred(tmp_config_dir, "svc-cred")

        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "second",
            ],
        )
        assert result.exit_code == 0

        from safeyolo.commands.vault import _load_vault

        vault, _ = _load_vault()
        cred = vault.get("svc-cred-2")
        assert cred is not None
        assert cred.value == "second"

        agent = load_agent("boris")
        assert agent["services"]["svc"]["token"] == "svc-cred-2"


# ---------------------------------------------------------------------------
# policy.toml writes
# ---------------------------------------------------------------------------


class TestAgentsYamlWrites:
    def test_service_entry_written(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )
        _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "x",
            ],
        )
        agent = load_agent("boris")
        assert agent["services"]["svc"] == {"capability": "r", "token": "svc-cred"}

    def test_existing_services_preserved(self, cli_runner, tmp_config_dir):
        _create_agent(
            tmp_config_dir,
            "boris",
            extra={
                "services": {"old": {"capability": "x", "token": "old-cred"}},
            },
        )
        _write_service(
            tmp_config_dir,
            "new",
            {"r": {"description": "Role", "routes": []}},
        )
        _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "new",
                "--capability",
                "r",
                "--token",
                "x",
            ],
        )
        agent = load_agent("boris")
        assert "old" in agent["services"]
        assert "new" in agent["services"]

    def test_same_service_overwritten(self, cli_runner, tmp_config_dir):
        _create_agent(
            tmp_config_dir,
            "boris",
            extra={
                "services": {"svc": {"capability": "old-cap", "token": "old-cred"}},
            },
        )
        _write_service(
            tmp_config_dir,
            "svc",
            {"new-cap": {"description": "New", "routes": []}},
        )
        _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "new-cap",
                "--token",
                "x",
            ],
        )
        agent = load_agent("boris")
        assert agent["services"]["svc"]["capability"] == "new-cap"


# ---------------------------------------------------------------------------
# Host binding check
# ---------------------------------------------------------------------------


class TestHostBindingCheck:
    def test_existing_binding_found(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
            default_host="api.example.com",
        )
        _write_policy(
            tmp_config_dir,
            hosts={
                "api.example.com": {"service": "svc", "rate_limit": 100},
            },
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "x",
            ],
        )
        assert result.exit_code == 0
        assert "Host binding found" in result.output

    def test_host_exists_but_no_service_binding(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
            default_host="api.example.com",
        )
        _write_policy(
            tmp_config_dir,
            hosts={
                "api.example.com": {"rate_limit": 100},
            },
        )
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "x",
            ],
        )
        assert result.exit_code == 0
        assert "Next step" in result.output
        assert "service: svc" in result.output

    def test_missing_host_warns_with_suggestion(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
            default_host="api.example.com",
        )
        _write_policy(tmp_config_dir, hosts={})
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "x",
            ],
        )
        assert result.exit_code == 0
        assert "Next step" in result.output
        assert "api.example.com" in result.output
        assert "service: svc" in result.output

    def test_no_default_host_warns(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        _write_service(
            tmp_config_dir,
            "svc",
            {"r": {"description": "Role", "routes": []}},
        )  # no default_host
        result = _invoke(
            cli_runner,
            [
                "authorize",
                "boris",
                "svc",
                "--capability",
                "r",
                "--token",
                "x",
            ],
        )
        assert result.exit_code == 0
        assert "next step" in result.output.lower()
        assert "<your-host>" in result.output.lower()


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_removes_entry(self, cli_runner, tmp_config_dir):
        _create_agent(
            tmp_config_dir,
            "boris",
            extra={
                "services": {"svc": {"capability": "r", "token": "svc-cred"}},
            },
        )
        result = _invoke(cli_runner, ["revoke", "boris", "svc"])
        assert result.exit_code == 0
        assert "Revoked" in result.output
        agent = load_agent("boris")
        assert "services" not in agent or "svc" not in agent.get("services", {})

    def test_rejects_unknown_agent(self, cli_runner, tmp_config_dir):
        result = _invoke(cli_runner, ["revoke", "ghost", "svc"])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_rejects_unbound_service(self, cli_runner, tmp_config_dir):
        _create_agent(tmp_config_dir, "boris")
        result = _invoke(cli_runner, ["revoke", "boris", "svc"])
        assert result.exit_code != 0
        assert "not authorized" in result.output.lower()

    def test_prints_credential_reminder(self, cli_runner, tmp_config_dir):
        _create_agent(
            tmp_config_dir,
            "boris",
            extra={
                "services": {"svc": {"capability": "r", "token": "svc-cred"}},
            },
        )
        _store_vault_cred(tmp_config_dir, "svc-cred")
        result = _invoke(cli_runner, ["revoke", "boris", "svc"])
        assert "svc-cred" in result.output
        assert "vault remove" in result.output

    def test_no_reminder_when_credential_not_in_vault(self, cli_runner, tmp_config_dir):
        _create_agent(
            tmp_config_dir,
            "boris",
            extra={
                "services": {"svc": {"capability": "r", "token": "ghost-cred"}},
            },
        )
        result = _invoke(cli_runner, ["revoke", "boris", "svc"])
        assert "Revoked" in result.output
        assert "vault remove" not in result.output

    def test_preserves_other_services(self, cli_runner, tmp_config_dir):
        _create_agent(
            tmp_config_dir,
            "boris",
            extra={
                "services": {
                    "svc1": {"capability": "r1", "token": "cred1"},
                    "svc2": {"capability": "r2", "token": "cred2"},
                },
            },
        )
        result = _invoke(cli_runner, ["revoke", "boris", "svc1"])
        assert result.exit_code == 0
        agent = load_agent("boris")
        assert "svc1" not in agent["services"]
        assert "svc2" in agent["services"]


# ---------------------------------------------------------------------------
# _validate_instance_name
# ---------------------------------------------------------------------------


class TestValidateInstanceName:
    def test_valid_simple_name(self):
        # Should not raise
        _validate_instance_name("boris")

    def test_valid_name_with_hyphens(self):
        _validate_instance_name("my-agent-1")

    def test_valid_single_char(self):
        _validate_instance_name("a")

    def test_empty_name_exits(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("")

    def test_too_long_name_exits(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("a" * 64)

    def test_max_length_name_accepted(self):
        _validate_instance_name("a" * 63)

    def test_uppercase_rejected(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("Boris")

    def test_underscore_rejected(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("my_agent")

    def test_leading_hyphen_rejected(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("-agent")

    def test_trailing_hyphen_rejected(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("agent-")

    def test_dot_rejected(self):
        with pytest.raises(typer.Exit):
            _validate_instance_name("my.agent")


# ---------------------------------------------------------------------------
# _parse_mount (mount security: protected paths)
# ---------------------------------------------------------------------------


class TestParseMountSecurity:
    def test_protected_path_requires_read_only(self, tmp_path, monkeypatch):
        """Mounting a protected path without :ro is refused."""
        host_dir = tmp_path / "refs"
        host_dir.mkdir()
        # Pass protected_paths directly to is_path_protected
        assert is_path_protected(str(host_dir), [str(tmp_path)]) is not None
        # _parse_mount checks is_path_protected internally via get_protected_paths
        # We mock get_protected_paths to return our test path
        from unittest.mock import patch
        with patch("safeyolo.commands.agent.is_path_protected", return_value=str(tmp_path)):
            with pytest.raises(typer.Exit):
                _parse_mount(f"{host_dir}:/container/refs")

    def test_protected_path_allowed_with_ro(self, tmp_path):
        """Protected path with :ro is accepted."""
        host_dir = tmp_path / "refs"
        host_dir.mkdir()
        from unittest.mock import patch
        with patch("safeyolo.commands.agent.is_path_protected", return_value=str(tmp_path)):
            result = _parse_mount(f"{host_dir}:/container/refs:ro")
            assert result.endswith(":ro")
            assert "/container/refs" in result

    def test_normal_path_writable(self, tmp_path):
        """Non-protected path can be mounted without :ro."""
        host_dir = tmp_path / "project"
        host_dir.mkdir()
        from unittest.mock import patch
        with patch("safeyolo.commands.agent.is_path_protected", return_value=None):
            result = _parse_mount(f"{host_dir}:/container/project")
            assert ":ro" not in result
            assert "/container/project" in result

    def test_invalid_mount_format_rejected(self):
        with pytest.raises(typer.Exit):
            _parse_mount("single-part-only")

    def test_invalid_mount_option_rejected(self, tmp_path):
        host_dir = tmp_path / "d"
        host_dir.mkdir()
        from unittest.mock import patch
        with patch("safeyolo.commands.agent.is_path_protected", return_value=None):
            with pytest.raises(typer.Exit):
                _parse_mount(f"{host_dir}:/container/d:rw")

    def test_nonexistent_host_path_rejected(self, tmp_path):
        with pytest.raises(typer.Exit):
            _parse_mount(f"{tmp_path}/nonexistent:/container/d")

    def test_relative_container_path_rejected(self, tmp_path):
        host_dir = tmp_path / "d"
        host_dir.mkdir()
        with pytest.raises(typer.Exit):
            _parse_mount(f"{host_dir}:relative/path")
