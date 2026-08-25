"""Regression tests for #336 — refuse `agent add` / `proxy start` when the
compiled policy has no permissions.

Fresh-install repro (from the issue):

    $ cat ~/.safeyolo/policy.toml
    [agents.test]
    folder = "..."

    $ safeyolo policy show --compiled --section permissions
    permissions: []

    $ safeyolo agent add test ...
    Agent 'test' added!               # gate accepted an unusable policy
    $ curl <anything>                 # → 403 at network_guard fail-closed

The guard runs before touching disk, so agents never land against an
unusable policy.
"""

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner


def _write_empty_policy(config_dir: Path) -> None:
    """Overwrite the fixture policy with just an [agents.X] block — no hosts,
    no permissions. This is what a fumbled `init` leaves behind."""
    (config_dir / "policy.toml").write_text(
        "[agents.test]\n"
        'folder = "/tmp/proj"\n'
    )


def _write_valid_policy(config_dir: Path) -> None:
    """A minimal policy with a host rule — compiles to at least one permission."""
    (config_dir / "policy.toml").write_text(
        'version = "2.0"\n\n'
        "[hosts]\n"
        '"*" = { rate = 600 }\n'
    )


class TestAssertPolicyHasPermissions:
    """The helper called by both `agent add` and `proxy start`."""

    def test_raises_on_missing_policy_file(self, tmp_path):
        from safeyolo.commands.policy import assert_policy_has_permissions

        empty_dir = tmp_path / "empty-config"
        empty_dir.mkdir()

        with pytest.raises(typer.Exit) as exc:
            assert_policy_has_permissions(empty_dir)
        assert exc.value.exit_code == 1

    def test_raises_on_empty_permissions(self, tmp_config_dir):
        from safeyolo.commands.policy import assert_policy_has_permissions

        _write_empty_policy(tmp_config_dir)

        with pytest.raises(typer.Exit) as exc:
            assert_policy_has_permissions(tmp_config_dir)
        assert exc.value.exit_code == 1

    def test_returns_silently_on_valid_policy(self, tmp_config_dir):
        from safeyolo.commands.policy import assert_policy_has_permissions

        _write_valid_policy(tmp_config_dir)

        # Must not raise.
        assert_policy_has_permissions(tmp_config_dir)


class TestAgentAddGate:
    """Integration: `agent add` refuses an empty policy before touching disk."""

    def test_agent_add_exits_before_touching_disk(self, cli_runner: CliRunner, tmp_config_dir, tmp_path):
        from safeyolo.commands.agent import agent_app

        _write_empty_policy(tmp_config_dir)
        folder = tmp_path / "proj"
        folder.mkdir()

        result = cli_runner.invoke(
            agent_app,
            ["add", "test", str(folder), "--dangerously-allow-unowned"],
        )

        assert result.exit_code == 1, result.output
        assert "zero permissions" in result.output
        assert "safeyolo init --force" in result.output

        # Nothing should have been written under the agents dir.
        agents_dir = tmp_config_dir / "agents"
        if agents_dir.exists():
            assert list(agents_dir.iterdir()) == []
