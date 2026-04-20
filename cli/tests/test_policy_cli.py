"""Tests for policy CLI commands -- host, egress, list."""

from datetime import UTC, datetime, timedelta

import tomlkit
from typer.testing import CliRunner

from safeyolo.cli import app

runner = CliRunner()


def _read_toml(config_dir):
    return tomlkit.parse((config_dir / "policy.toml").read_text())


# =========================================================================
# _parse_expires
# =========================================================================


class TestParseExpires:
    """Contract: _parse_expires accepts duration shorthands (1h/8h/1d/7d)
    or ISO datetime strings, and returns a datetime.  Invalid input raises."""

    def test_1h_shorthand_returns_roughly_one_hour_ahead(self):
        from safeyolo.commands.policy_host import _parse_expires

        before = datetime.now(UTC)
        result = _parse_expires("1h")
        after = datetime.now(UTC)
        assert before + timedelta(hours=1) <= result <= after + timedelta(hours=1)

    def test_8h_shorthand_returns_roughly_eight_hours_ahead(self):
        from safeyolo.commands.policy_host import _parse_expires

        before = datetime.now(UTC)
        result = _parse_expires("8h")
        after = datetime.now(UTC)
        assert before + timedelta(hours=8) <= result <= after + timedelta(hours=8)

    def test_1d_shorthand_returns_roughly_one_day_ahead(self):
        from safeyolo.commands.policy_host import _parse_expires

        before = datetime.now(UTC)
        result = _parse_expires("1d")
        after = datetime.now(UTC)
        assert before + timedelta(days=1) <= result <= after + timedelta(days=1)

    def test_7d_shorthand_returns_roughly_seven_days_ahead(self):
        from safeyolo.commands.policy_host import _parse_expires

        before = datetime.now(UTC)
        result = _parse_expires("7d")
        after = datetime.now(UTC)
        assert before + timedelta(days=7) <= result <= after + timedelta(days=7)

    def test_iso_datetime_returns_exact_value(self):
        from safeyolo.commands.policy_host import _parse_expires

        result = _parse_expires("2026-12-31T23:59:59+00:00")
        assert result == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)

    def test_invalid_string_raises_value_error(self):
        import pytest

        from safeyolo.commands.policy_host import _parse_expires

        with pytest.raises(ValueError):
            _parse_expires("not-a-duration")

    def test_empty_string_raises_value_error(self):
        import pytest

        from safeyolo.commands.policy_host import _parse_expires

        with pytest.raises(ValueError):
            _parse_expires("")

    def test_unsupported_duration_raises(self):
        """'2h' is not in the allowed shorthands -- falls through to ISO parse, which fails."""
        import pytest

        from safeyolo.commands.policy_host import _parse_expires

        with pytest.raises(ValueError):
            _parse_expires("2h")


# =========================================================================
# policy host add
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
        boris.add("folder", "/tmp/proj")
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

    def test_add_same_host_twice_merges_rate(self, tmp_config_dir):
        """Adding a host that already exists updates the rate, not clobbers."""
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "100"])
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "900"])

        doc = _read_toml(tmp_config_dir)
        entry = doc["hosts"]["api.stripe.com"]
        assert entry["rate"] == 900

    def test_add_with_expires_writes_datetime(self, tmp_config_dir):
        """--expires stores a datetime in the TOML entry."""
        before = datetime.now(UTC)
        result = runner.invoke(app, ["policy", "host", "add", "temp.io", "--rate", "50", "--expires", "1h"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        entry = doc["hosts"]["temp.io"]
        assert entry["rate"] == 50
        # expires should be a datetime roughly 1h from now
        exp = entry["expires"]
        assert isinstance(exp, datetime)
        assert exp >= before + timedelta(hours=1) - timedelta(seconds=5)

    def test_add_creates_agent_section_if_missing(self, tmp_config_dir):
        """When --agent is used and no agents section exists, it creates one."""
        result = runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "100", "--agent", "newagent"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert "api.stripe.com" in doc["agents"]["newagent"]["hosts"]


# =========================================================================
# policy host remove
# =========================================================================


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


# =========================================================================
# policy host deny
# =========================================================================


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

    def test_deny_merges_into_existing_entry_preserving_rate(self, tmp_config_dir):
        """B2 fix: denying a host that already has rate/credentials merges,
        not clobbers.  The rate must survive the deny."""
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600"])
        result = runner.invoke(app, ["policy", "host", "deny", "api.stripe.com", "--expires", "1d"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        entry = doc["hosts"]["api.stripe.com"]
        assert entry["egress"] == "deny"
        assert entry["rate"] == 600  # preserved, not clobbered

    def test_deny_agent_scoped(self, tmp_config_dir):
        """host deny --agent writes into the agent's hosts section."""
        result = runner.invoke(app, ["policy", "host", "deny", "sketchy.io", "--agent", "boris"])
        assert result.exit_code == 0
        assert "boris" in result.output

        doc = _read_toml(tmp_config_dir)
        entry = doc["agents"]["boris"]["hosts"]["sketchy.io"]
        assert entry["egress"] == "deny"


# =========================================================================
# policy host list
# =========================================================================


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

    def test_list_agent_scoped_shows_agent_hosts(self, tmp_config_dir):
        """--agent boris shows hosts under agents.boris.hosts."""
        runner.invoke(app, ["policy", "host", "add", "agent-only.com", "--rate", "100", "--agent", "boris"])
        result = runner.invoke(app, ["policy", "host", "list", "--agent", "boris"])
        assert result.exit_code == 0
        assert "agent-only.com" in result.output

    def test_list_agent_scoped_empty(self, tmp_config_dir):
        """--agent for a nonexistent agent shows 'no host entries'."""
        result = runner.invoke(app, ["policy", "host", "list", "--agent", "nobody"])
        assert result.exit_code == 0
        assert "No host entries" in result.output


# =========================================================================
# policy host bypass
# =========================================================================


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

    def test_bypass_deduplicates_same_addon(self, tmp_config_dir):
        """Adding the same bypass addon twice does not create duplicates."""
        runner.invoke(app, ["policy", "host", "add", "api.stripe.com", "--rate", "600"])
        runner.invoke(app, ["policy", "host", "bypass", "api.stripe.com", "circuit_breaker"])
        runner.invoke(app, ["policy", "host", "bypass", "api.stripe.com", "circuit_breaker"])

        doc = _read_toml(tmp_config_dir)
        bypass_list = doc["hosts"]["api.stripe.com"]["bypass"]
        assert bypass_list.count("circuit_breaker") == 1


# =========================================================================
# policy host add-list
# =========================================================================


class TestPolicyHostAddList:
    """Contract: host add-list writes '$name' = {config} into [hosts],
    after verifying the list exists in [lists].  Rejects invalid egress values."""

    def test_add_list_with_egress_deny(self, tmp_config_dir):
        """Writes $name reference with egress=deny."""
        # Set up: register a list first
        list_file = tmp_config_dir / "lists" / "known_bad.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("evil.com\nbad.org\n")
        runner.invoke(app, ["policy", "list", "add", "known_bad", "lists/known_bad.txt"])

        result = runner.invoke(app, ["policy", "host", "add-list", "known_bad", "--egress", "deny"])
        assert result.exit_code == 0
        assert "Added list reference" in result.output

        doc = _read_toml(tmp_config_dir)
        assert "$known_bad" in doc["hosts"]
        assert doc["hosts"]["$known_bad"]["egress"] == "deny"

    def test_add_list_with_rate(self, tmp_config_dir):
        """Writes $name reference with rate limit."""
        list_file = tmp_config_dir / "lists" / "registries.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("pypi.org\nnpmjs.com\n")
        runner.invoke(app, ["policy", "list", "add", "registries", "lists/registries.txt"])

        result = runner.invoke(app, ["policy", "host", "add-list", "registries", "--rate", "1200"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert doc["hosts"]["$registries"]["rate"] == 1200

    def test_add_list_unknown_name_errors(self, tmp_config_dir):
        """Referencing a list not in [lists] exits with error."""
        result = runner.invoke(app, ["policy", "host", "add-list", "nonexistent", "--egress", "deny"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_add_list_invalid_egress_errors(self, tmp_config_dir):
        """Invalid egress value (not allow/deny/prompt) exits with error."""
        list_file = tmp_config_dir / "lists" / "test.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("x.com\n")
        runner.invoke(app, ["policy", "list", "add", "test", "lists/test.txt"])

        result = runner.invoke(app, ["policy", "host", "add-list", "test", "--egress", "nope"])
        assert result.exit_code == 1
        assert "Invalid egress" in result.output


# =========================================================================
# policy egress set
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

    def test_set_creates_wildcard_when_missing(self, tmp_config_dir):
        """B3 fix: egress set creates '*' entry when hosts has no wildcard."""
        # Remove the wildcard from the fixture
        doc = _read_toml(tmp_config_dir)
        hosts = tomlkit.table()
        hosts.add("api.stripe.com", tomlkit.inline_table())
        doc["hosts"] = hosts
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        result = runner.invoke(app, ["policy", "egress", "set", "prompt"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert "*" in doc["hosts"]
        assert doc["hosts"]["*"]["egress"] == "prompt"

    def test_set_creates_hosts_section_when_missing(self, tmp_config_dir):
        """If the entire [hosts] section is missing, egress set creates it."""
        doc = _read_toml(tmp_config_dir)
        del doc["hosts"]
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        result = runner.invoke(app, ["policy", "egress", "set", "deny"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert doc["hosts"]["*"]["egress"] == "deny"

    def test_set_agent_creates_agents_section_if_missing(self, tmp_config_dir):
        """Setting agent egress when no [agents] section exists creates it."""
        result = runner.invoke(app, ["policy", "egress", "set", "prompt", "--agent", "newagent"])
        assert result.exit_code == 0

        doc = _read_toml(tmp_config_dir)
        assert doc["agents"]["newagent"]["egress"] == "prompt"


# =========================================================================
# policy egress show
# =========================================================================


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

    def test_show_no_wildcard_reports_deny(self, tmp_config_dir):
        """B4 fix: when no '*' wildcard exists in hosts, egress show reports 'deny'
        because network-guard blocks everything without a wildcard."""
        doc = _read_toml(tmp_config_dir)
        hosts = tomlkit.table()
        hosts.add("api.stripe.com", tomlkit.inline_table())
        doc["hosts"] = hosts
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        result = runner.invoke(app, ["policy", "egress", "show"])
        assert result.exit_code == 0
        assert "deny" in result.output

    def test_show_wildcard_without_egress_field_defaults_to_allow(self, tmp_config_dir):
        """A wildcard entry with no explicit egress field means 'allow'."""
        # The fixture already has '*' = { rate = 600 } with no egress field
        result = runner.invoke(app, ["policy", "egress", "show"])
        assert result.exit_code == 0
        assert "allow" in result.output

    def test_show_agent_inherits_deny_when_no_wildcard(self, tmp_config_dir):
        """Agent with no own posture inherits the proxy-wide 'deny' when no wildcard."""
        doc = _read_toml(tmp_config_dir)
        hosts = tomlkit.table()
        doc["hosts"] = hosts
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        result = runner.invoke(app, ["policy", "egress", "show", "--agent", "boris"])
        assert result.exit_code == 0
        assert "deny" in result.output


# =========================================================================
# policy list add / remove / show
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

    def test_show_empty_lists_section(self, tmp_config_dir):
        """When no lists are defined, shows informational message."""
        result = runner.invoke(app, ["policy", "list", "show"])
        assert result.exit_code == 0
        assert "No named lists" in result.output

    def test_show_specific_nonexistent_name(self, tmp_config_dir):
        """Asking for a list name that doesn't exist exits with error."""
        # First create at least one list so [lists] section exists
        list_file = tmp_config_dir / "lists" / "test.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("host1.com\n")
        runner.invoke(app, ["policy", "list", "add", "test", "lists/test.txt"])

        result = runner.invoke(app, ["policy", "list", "show", "ghost"])
        assert result.exit_code == 1
        assert "Not found" in result.output

    def test_show_specific_missing_file(self, tmp_config_dir):
        """List is registered but the file was deleted -- shows error."""
        list_file = tmp_config_dir / "lists" / "temp.txt"
        list_file.parent.mkdir(exist_ok=True)
        list_file.write_text("host1.com\n")
        runner.invoke(app, ["policy", "list", "add", "temp", "lists/temp.txt"])
        # Now delete the file
        list_file.unlink()

        result = runner.invoke(app, ["policy", "list", "show", "temp"])
        assert result.exit_code == 1
        assert "not found" in result.output
