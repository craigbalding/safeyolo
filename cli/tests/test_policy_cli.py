"""Tests for policy CLI commands — host, egress, list."""

import tomlkit
from typer.testing import CliRunner

from safeyolo.cli import app

runner = CliRunner()


def _read_toml(config_dir):
    return tomlkit.parse((config_dir / "policy.toml").read_text())


# =========================================================================
# policy host
# =========================================================================


class TestPolicyHostAdd:
    def test_add_host_with_rate(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600"])
        assert result.exit_code == 0
        assert "Added host" in result.output

        doc = _read_toml(tmp_config_dir)
        assert "api.stripe.com" in doc["hosts"]

    def test_add_host_agent_scoped(self, tmp_config_dir):
        # Create agent section first
        doc = _read_toml(tmp_config_dir)
        agents = tomlkit.table()
        boris = tomlkit.table()
        boris.add("template", "claude-code")
        agents.add("boris", boris)
        doc.add("agents", agents)
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        result = runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600", "--agent", "boris"])
        assert result.exit_code == 0
        assert "boris" in result.output

        doc = _read_toml(tmp_config_dir)
        assert "api.stripe.com" in doc["agents"]["boris"]["hosts"]

    def test_add_host_preserves_existing(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "host", "add", "first.com", "--rate", "100"])
        assert result.exit_code == 0
        result = runner.invoke(app, ["policy", "host", "add", "second.com", "--rate", "200"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert "first.com" in doc["hosts"]
        assert "second.com" in doc["hosts"]


class TestPolicyHostRemove:
    def test_remove_existing(self, tmp_config_dir):
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600"])
        result = runner.invoke(app, ["policy", "host", "remove", "api.stripe.com"])
        assert result.exit_code == 0
        assert "Removed" in result.output

        doc = _read_toml(tmp_config_dir)
        assert "api.stripe.com" not in doc["hosts"]

    def test_remove_nonexistent(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "host", "remove", "ghost.com"])
        assert result.exit_code == 1
        assert "Not found" in result.output


class TestPolicyHostDeny:
    def test_deny_with_default_expiry(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "host", "deny", "sketchy.io"])
        assert result.exit_code == 0
        assert "Denied" in result.output

        doc = _read_toml(tmp_config_dir)
        entry = doc["hosts"]["sketchy.io"]
        assert entry["egress"] == "deny"
        assert "expires" in entry

    def test_deny_with_custom_expiry(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "host", "deny", "evil.com", "--expires", "7d"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert doc["hosts"]["evil.com"]["egress"] == "deny"


class TestPolicyHostList:
    def test_list_shows_hosts(self, tmp_config_dir):
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600"])
        result = runner.invoke(app, ["policy", "host", "list"])
        assert result.exit_code == 0
        assert "api.stripe.com" in result.output

    def test_list_empty(self, tmp_config_dir):
        # Remove the default wildcard entry for a clean test
        doc = _read_toml(tmp_config_dir)
        doc["hosts"] = tomlkit.table()
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        result = runner.invoke(app, ["policy", "host", "list"])
        assert result.exit_code == 0
        assert "No host entries" in result.output


class TestPolicyHostBypass:
    def test_bypass_new_host(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "host", "bypass", "internal.svc", "circuit_breaker"])
        assert result.exit_code == 0
        assert "Bypass added" in result.output

        doc = _read_toml(tmp_config_dir)
        assert "circuit_breaker" in doc["hosts"]["internal.svc"]["bypass"]

    def test_bypass_existing_host(self, tmp_config_dir):
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600"])
        result = runner.invoke(app, ["policy", "host", "bypass", "api.stripe.com", "pattern_scanner"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert "pattern_scanner" in doc["hosts"]["api.stripe.com"]["bypass"]


# =========================================================================
# policy egress
# =========================================================================


class TestPolicyEgressSet:
    def test_set_prompt(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "egress", "set", "prompt"])
        assert result.exit_code == 0
        assert "prompt" in result.output

        doc = _read_toml(tmp_config_dir)
        assert doc["hosts"]["*"]["egress"] == "prompt"

    def test_set_deny(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "egress", "set", "deny"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert doc["hosts"]["*"]["egress"] == "deny"

    def test_set_agent_level(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "egress", "set", "deny", "--agent", "boris"])
        assert result.exit_code == 0
        assert "boris" in result.output

        doc = _read_toml(tmp_config_dir)
        assert doc["agents"]["boris"]["egress"] == "deny"

    def test_set_invalid_posture(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "egress", "set", "nope"])
        assert result.exit_code == 1
        assert "Invalid posture" in result.output


class TestPolicyEgressShow:
    def test_show_proxy_wide(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "egress", "show"])
        assert result.exit_code == 0
        assert "Proxy-wide" in result.output

    def test_show_agent_inherits(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "egress", "show", "--agent", "boris"])
        assert result.exit_code == 0
        assert "inherits" in result.output

    def test_show_agent_with_own_posture(self, tmp_config_dir):
        runner.invoke(app, ["policy", "egress", "set", "deny", "--agent", "boris"])
        result = runner.invoke(app, ["policy", "egress", "show", "--agent", "boris"])
        assert result.exit_code == 0
        assert "deny" in result.output


# =========================================================================
# policy list
# =========================================================================


class TestPolicyListAdd:
    def test_add_list(self, tmp_config_dir):
        # Create a list file
        list_file = tmp_config_dir / "lists" / "test.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("host1.com\nhost2.com\n")

        result = runner.invoke(app, ["policy", "list", "add", "test", "lists/test.txt"])
        assert result.exit_code == 0
        assert "2 entries" in result.output

        doc = _read_toml(tmp_config_dir)
        assert doc["lists"]["test"] == "lists/test.txt"

    def test_add_list_missing_file(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "list", "add", "bad", "lists/nonexistent.txt"])
        assert result.exit_code == 1
        assert "not found" in result.output


class TestPolicyListRemove:
    def test_remove_list(self, tmp_config_dir):
        list_file = tmp_config_dir / "lists" / "test.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("host1.com\n")
        runner.invoke(app, ["policy", "list", "add", "test", "lists/test.txt"])

        result = runner.invoke(app, ["policy", "list", "remove", "test"])
        assert result.exit_code == 0
        assert "Removed" in result.output

    def test_remove_nonexistent(self, tmp_config_dir):
        result = runner.invoke(app, ["policy", "list", "remove", "nope"])
        assert result.exit_code == 1
        assert "Not found" in result.output


class TestPolicyListShow:
    def test_show_all(self, tmp_config_dir):
        list_file = tmp_config_dir / "lists" / "test.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("host1.com\nhost2.com\n")
        runner.invoke(app, ["policy", "list", "add", "test", "lists/test.txt"])

        result = runner.invoke(app, ["policy", "list", "show"])
        assert result.exit_code == 0
        assert "$test" in result.output
        assert "2" in result.output

    def test_show_specific(self, tmp_config_dir):
        list_file = tmp_config_dir / "lists" / "test.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("host1.com\nhost2.com\n")
        runner.invoke(app, ["policy", "list", "add", "test", "lists/test.txt"])

        result = runner.invoke(app, ["policy", "list", "show", "test"])
        assert result.exit_code == 0
        assert "host1.com" in result.output
        assert "host2.com" in result.output
