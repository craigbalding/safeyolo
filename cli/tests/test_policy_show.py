"""Tests for safeyolo policy show command."""

import yaml
from typer.testing import CliRunner

from safeyolo.cli import app

runner = CliRunner()


def _write_yaml(path, data):
    path.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))


import pytest


class TestPolicyShow:
    """Tests for 'safeyolo policy show'."""

    @pytest.fixture(autouse=True)
    def _remove_default_toml(self, tmp_config_dir):
        """Remove conftest's policy.toml so tests can use policy.yaml."""
        toml = tmp_config_dir / "policy.toml"
        if toml.exists():
            toml.unlink()

    def test_basic_show(self, tmp_config_dir):
        """Loads policy.yaml and outputs its content."""
        policy = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
            }
        }
        _write_yaml(tmp_config_dir / "policy.yaml", policy)

        result = runner.invoke(app, ["policy", "show"])
        assert result.exit_code == 0
        assert "api.openai.com" in result.output
        assert "openai:*" in result.output

    def test_merge_addons_defaults(self, tmp_config_dir):
        """addons.yaml keys appear as defaults; policy.yaml keys override."""
        policy = {
            "hosts": {"api.openai.com": {"rate_limit": 3000}},
            "addons": {"credential-guard": {"mode": "block"}},
        }
        addons = {
            "scan_patterns": [{"name": "test", "pattern": "sk-.*"}],
            "addons": {
                "credential-guard": {"mode": "warn"},
                "network-guard": {"mode": "block"},
            },
        }
        _write_yaml(tmp_config_dir / "policy.yaml", policy)
        _write_yaml(tmp_config_dir / "addons.yaml", addons)

        result = runner.invoke(app, ["policy", "show"])
        assert result.exit_code == 0
        # scan_patterns comes from addons.yaml (not in policy.yaml)
        assert "scan_patterns" in result.output
        # credential-guard mode stays "block" (policy.yaml wins)
        assert "block" in result.output
        # network-guard comes from addons.yaml deep merge
        assert "network-guard" in result.output

    def test_agents_in_policy(self, tmp_config_dir):
        """Agents in policy.yaml appear in output."""
        policy = {
            "hosts": {"example.com": None},
            "agents": {
                "claude": {
                    "services": {"gmail": {"capability": "reader", "token": "gmail-key"}},
                    "contract_bindings": [{"service": "minifuse"}],
                },
                "file-agent": {"services": {"svc": {"capability": "r", "token": "svc-key"}}},
            },
        }
        _write_yaml(tmp_config_dir / "policy.yaml", policy)

        result = runner.invoke(app, ["policy", "show"])
        assert result.exit_code == 0
        assert "claude" in result.output
        assert "gmail" in result.output
        assert "file-agent" in result.output
        assert "contract_bindings" in result.output

    def test_section_filter(self, tmp_config_dir):
        """--section filters to a single top-level key."""
        policy = {
            "hosts": {"api.openai.com": {"rate_limit": 3000}},
            "metadata": {"name": "test-policy"},
        }
        _write_yaml(tmp_config_dir / "policy.yaml", policy)

        result = runner.invoke(app, ["policy", "show", "--section", "hosts"])
        assert result.exit_code == 0
        assert "api.openai.com" in result.output
        assert "metadata" not in result.output

    def test_section_unknown_errors(self, tmp_config_dir):
        """--section with unknown key prints error and exits 1."""
        policy = {"hosts": {"example.com": None}}
        _write_yaml(tmp_config_dir / "policy.yaml", policy)

        result = runner.invoke(app, ["policy", "show", "--section", "nope"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_compiled(self, tmp_config_dir):
        """--compiled produces IAM format with permissions key."""
        policy = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"], "rate_limit": 3000},
            }
        }
        _write_yaml(tmp_config_dir / "policy.yaml", policy)

        result = runner.invoke(app, ["policy", "show", "--compiled"])
        assert result.exit_code == 0
        assert "permissions" in result.output
        # Host-centric key should not appear in compiled output
        assert "hosts" not in result.output

    def test_compiled_section(self, tmp_config_dir):
        """--compiled --section permissions works."""
        policy = {
            "hosts": {
                "api.openai.com": {"credentials": ["openai:*"]},
            }
        }
        _write_yaml(tmp_config_dir / "policy.yaml", policy)

        result = runner.invoke(app, ["policy", "show", "--compiled", "--section", "permissions"])
        assert result.exit_code == 0
        assert "permissions" in result.output

    def test_missing_policy_yaml(self, tmp_config_dir):
        """Missing policy.yaml prints error and exits 1."""
        # tmp_config_dir exists but has no policy.yaml
        result = runner.invoke(app, ["policy", "show"])
        assert result.exit_code == 1
        assert "not found" in result.output
