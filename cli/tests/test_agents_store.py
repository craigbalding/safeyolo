"""Tests for agents_store module (policy.toml backend)."""

import pytest
import tomlkit

from safeyolo.agents_store import (
    _load_doc,
    load_agent,
    load_all_agents,
    remove_agent,
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
        meta = {"template": "claude-code", "folder": "/tmp/proj"}
        save_agent("boris", meta)
        assert load_agent("boris") == meta

    def test_preserves_others(self, tmp_config_dir):
        """Saving boris doesn't clobber alice."""
        _write_policy(tmp_config_dir)
        save_agent("alice", {"template": "t1", "folder": "/a"})
        save_agent("boris", {"template": "t2", "folder": "/b"})

        assert load_agent("alice") == {"template": "t1", "folder": "/a"}
        assert load_agent("boris") == {"template": "t2", "folder": "/b"}

    def test_preserves_host_config(self, tmp_config_dir):
        """Saving an agent doesn't clobber the [hosts] section."""
        _write_policy(tmp_config_dir)
        save_agent("boris", {"template": "claude-code", "folder": "/tmp/proj"})
        content = (tmp_config_dir / "policy.toml").read_text()
        assert '[hosts]' in content
        assert 'version = "2.0"' in content

    def test_services_round_trip(self, tmp_config_dir):
        """Services nested tables survive round-trip."""
        _write_policy(tmp_config_dir)
        meta = {
            "template": "claude-code",
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

        save_agent("boris", {"template": "claude-code", "folder": "/tmp/proj"})

        content = (tmp_config_dir / "policy.toml").read_text()
        reparsed = tomlkit.parse(content)
        assert reparsed["version"] == "2.0"
        assert "api.openai.com" in reparsed["hosts"]
        assert reparsed["required"] == ["credential_guard", "network_guard"]
        assert reparsed["agents"]["boris"]["template"] == "claude-code"


class TestRemoveAgent:
    def test_remove_existing(self, tmp_config_dir):
        """Returns True when agent exists."""
        _write_policy(tmp_config_dir)
        save_agent("boris", {"template": "t", "folder": "/f"})
        assert remove_agent("boris") is True
        assert load_agent("boris") == {}

    def test_remove_nonexistent(self, tmp_config_dir):
        """Returns False when agent doesn't exist."""
        _write_policy(tmp_config_dir)
        assert remove_agent("ghost") is False
