"""Tests for agents_store module (policy.toml backend)."""

import pytest
import tomlkit

from safeyolo.agents_store import (
    _load_doc,
    load_agent,
    load_all_agents,
    remove_agent,
    reserve_agent_network_slot,
    reserve_agent_tailnet_port,
    reserve_agent_tailnet_port_change,
    restore_agent_tailnet_port,
    save_agent,
)


def _write_policy(config_dir, agents=None):
    """Write a minimal policy.toml, optionally with agents."""
    doc = tomlkit.document()
    doc.add("version", "2.0")
    hosts = tomlkit.table()
    it = tomlkit.inline_table()
    it.append("rate", 600)
    hosts.add("*", it)
    doc.add("hosts", hosts)
    if agents:
        agents_table = tomlkit.table()
        for name, meta in agents.items():
            t = tomlkit.table()
            for k, v in meta.items():
                t.add(k, v)
            agents_table.add(name, t)
        doc.add("agents", agents_table)
    (config_dir / "policy.toml").write_text(tomlkit.dumps(doc))


class TestLoadAllAgents:
    def test_empty_when_no_agents_section(self, tmp_config_dir):
        """Returns {} when policy.toml has no [agents] section."""
        _write_policy(tmp_config_dir)
        assert load_all_agents() == {}

    def test_empty_when_file_missing(self, tmp_config_dir):
        """Returns {} when policy.toml doesn't exist."""
        assert load_all_agents() == {}


class TestSaveAndLoadAgent:
    def test_round_trip(self, tmp_config_dir):
        """Save then load returns same data."""
        _write_policy(tmp_config_dir)
        meta = {"host_script": "/tmp/claude.sh", "folder": "/tmp/proj"}
        save_agent("boris", meta)
        assert load_agent("boris") == meta

    def test_preserves_others(self, tmp_config_dir):
        """Saving boris doesn't clobber alice."""
        _write_policy(tmp_config_dir)
        save_agent("alice", {"host_script": "/tmp/t1.sh", "folder": "/a"})
        save_agent("boris", {"host_script": "/tmp/t2.sh", "folder": "/b"})

        assert load_agent("alice") == {"host_script": "/tmp/t1.sh", "folder": "/a"}
        assert load_agent("boris") == {"host_script": "/tmp/t2.sh", "folder": "/b"}

    def test_preserves_host_config(self, tmp_config_dir):
        """Saving an agent doesn't clobber the [hosts] section."""
        _write_policy(tmp_config_dir)
        save_agent("boris", {"host_script": "/tmp/claude.sh", "folder": "/tmp/proj"})
        content = (tmp_config_dir / "policy.toml").read_text()
        assert '[hosts]' in content
        assert 'version = "2.0"' in content

    def test_services_round_trip(self, tmp_config_dir):
        """Services nested tables survive round-trip."""
        _write_policy(tmp_config_dir)
        meta = {
            "host_script": "/tmp/claude.sh",
            "folder": "/tmp/proj",
            "services": {"gmail": {"capability": "read_and_send", "token": "gmail-oauth2"}},
        }
        save_agent("boris", meta)
        loaded = load_agent("boris")
        assert loaded["services"]["gmail"]["capability"] == "read_and_send"
        assert loaded["services"]["gmail"]["token"] == "gmail-oauth2"


class TestLoadDoc:
    def test_corrupted_policy_raises(self, tmp_config_dir):
        """Parse error propagates as exception instead of silently returning empty doc.

        Pins the fix: a corrupted policy.toml must NOT be silently replaced
        with an empty document, as that would destroy all policy data on next save.
        """
        (tmp_config_dir / "policy.toml").write_text("[[broken toml syntax")
        with pytest.raises(Exception):
            _load_doc()

    def test_load_doc_missing_file_returns_empty(self, tmp_config_dir):
        """Returns empty TOMLDocument when policy.toml does not exist."""
        (tmp_config_dir / "policy.toml").unlink()
        doc = _load_doc()
        assert tomlkit.dumps(doc) == ""


class TestSavePreservesAllSections:
    def test_save_preserves_all_sections_on_update(self, tmp_config_dir):
        """Saving an agent preserves every non-agents section in the file.

        Regression test: a read-modify-write cycle must not drop sections
        like [hosts], top-level keys, or comments.
        """
        doc = tomlkit.document()
        doc.add("version", "2.0")
        hosts = tomlkit.table()
        it = tomlkit.inline_table()
        it.append("rate", 600)
        hosts.add("*", it)
        hosts.add("api.openai.com", tomlkit.inline_table())
        doc.add("hosts", hosts)
        doc.add("required", ["credential_guard", "network_guard"])
        (tmp_config_dir / "policy.toml").write_text(tomlkit.dumps(doc))

        save_agent("boris", {"host_script": "/tmp/claude.sh", "folder": "/tmp/proj"})

        content = (tmp_config_dir / "policy.toml").read_text()
        reparsed = tomlkit.parse(content)
        assert reparsed["version"] == "2.0"
        assert "api.openai.com" in reparsed["hosts"]
        assert reparsed["required"] == ["credential_guard", "network_guard"]
        assert reparsed["agents"]["boris"]["host_script"] == "/tmp/claude.sh"


class TestRemoveAgent:
    def test_remove_existing(self, tmp_config_dir):
        """Returns True when agent exists."""
        _write_policy(tmp_config_dir)
        save_agent("boris", {"host_script": "/tmp/t.sh", "folder": "/f"})
        assert remove_agent("boris") is True
        assert load_agent("boris") == {}

    def test_remove_nonexistent(self, tmp_config_dir):
        """Returns False when agent doesn't exist."""
        _write_policy(tmp_config_dir)
        assert remove_agent("ghost") is False


class TestReserveAgentTailnetPort:
    def test_allocates_stable_distinct_ports(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a"}, "boris": {"folder": "/b"}},
        )

        assert reserve_agent_tailnet_port("alice") == 8443
        assert reserve_agent_tailnet_port("boris") == 8444
        assert reserve_agent_tailnet_port("alice") == 8443
        assert load_agent("alice")["tailnet_port"] == 8443

    def test_explicit_port_cannot_collide(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a"}, "boris": {"folder": "/b"}},
        )
        reserve_agent_tailnet_port("alice", 10443)

        with pytest.raises(ValueError, match="already assigned"):
            reserve_agent_tailnet_port("boris", 10443)

    def test_explicit_port_replaces_existing_reservation(self, tmp_config_dir):
        _write_policy(tmp_config_dir, agents={"alice": {"folder": "/a"}})
        reserve_agent_tailnet_port("alice")

        assert reserve_agent_tailnet_port("alice", 11443) == 11443
        assert load_agent("alice")["tailnet_port"] == 11443

    def test_failed_start_can_restore_previous_reservation(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a", "tailnet_port": 8443}},
        )

        assert reserve_agent_tailnet_port_change("alice", 8444) == (8444, 8443)
        assert restore_agent_tailnet_port("alice", 8444, 8443)
        assert load_agent("alice")["tailnet_port"] == 8443

    def test_restore_does_not_overwrite_newer_reservation(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a", "tailnet_port": 8443}},
        )
        reserve_agent_tailnet_port("alice", 8444)
        reserve_agent_tailnet_port("alice", 8445)

        assert not restore_agent_tailnet_port("alice", 8444, 8443)
        assert load_agent("alice")["tailnet_port"] == 8445

    def test_rejects_invalid_explicit_port(self, tmp_config_dir):
        _write_policy(tmp_config_dir, agents={"alice": {"folder": "/a"}})

        with pytest.raises(ValueError, match="1-65535"):
            reserve_agent_tailnet_port("alice", 0)

    def test_rejects_invalid_saved_port(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a", "tailnet_port": 70000}},
        )

        with pytest.raises(ValueError, match="invalid tailnet HTTPS port"):
            reserve_agent_tailnet_port("alice")

    def test_rejects_duplicate_saved_port(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={
                "alice": {"folder": "/a", "tailnet_port": 8443},
                "boris": {"folder": "/b", "tailnet_port": 8443},
            },
        )

        with pytest.raises(ValueError, match="already assigned"):
            reserve_agent_tailnet_port("alice")

    def test_rejects_boolean_explicit_port(self, tmp_config_dir):
        _write_policy(tmp_config_dir, agents={"alice": {"folder": "/a"}})

        with pytest.raises(ValueError, match="1-65535"):
            reserve_agent_tailnet_port("alice", True)

    def test_rejects_invalid_saved_port_type(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a", "tailnet_port": "8443"}},
        )

        with pytest.raises(ValueError, match="invalid tailnet HTTPS port"):
            reserve_agent_tailnet_port("alice")


class TestReserveAgentNetworkSlot:
    def test_allocates_stable_distinct_slots(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"zulu": {"folder": "/z"}, "alpha": {"folder": "/a"}},
        )

        assert reserve_agent_network_slot("zulu") == 0
        assert reserve_agent_network_slot("alpha") == 1
        assert reserve_agent_network_slot("zulu") == 0
        assert load_agent("zulu")["network_slot"] == 0

    def test_avoids_running_legacy_agent_slot(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"legacy": {"folder": "/old"}, "new": {"folder": "/new"}},
        )
        data_dir = tmp_config_dir / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "agent_map.json").write_text(
            '{"legacy": {"ip": "10.200.0.1"}}\n'
        )

        assert reserve_agent_network_slot("new") == 1

    def test_adopts_unique_running_legacy_agent_slot(self, tmp_config_dir):
        _write_policy(tmp_config_dir, agents={"legacy": {"folder": "/old"}})
        data_dir = tmp_config_dir / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "agent_map.json").write_text(
            '{"legacy": {"ip": "10.200.1.0"}}\n'
        )

        assert reserve_agent_network_slot("legacy") == 255
        assert load_agent("legacy")["network_slot"] == 255

    def test_does_not_adopt_conflicting_legacy_slot(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={"alice": {"folder": "/a"}, "boris": {"folder": "/b"}},
        )
        data_dir = tmp_config_dir / "data"
        data_dir.mkdir(exist_ok=True)
        (data_dir / "agent_map.json").write_text(
            '{"alice": {"ip": "10.200.0.3"}, '
            '"boris": {"ip": "10.200.0.3"}}\n'
        )

        assert reserve_agent_network_slot("alice") == 0
        assert reserve_agent_network_slot("boris") == 1

    def test_rejects_duplicate_saved_slots(self, tmp_config_dir):
        _write_policy(
            tmp_config_dir,
            agents={
                "alice": {"folder": "/a", "network_slot": 2},
                "boris": {"folder": "/b", "network_slot": 2},
            },
        )

        with pytest.raises(ValueError, match="already assigned"):
            reserve_agent_network_slot("alice")
