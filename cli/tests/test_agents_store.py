"""Tests for agents_store module."""

import json

from safeyolo.agents_store import (
    load_agent,
    load_all_agents,
    migrate_from_json,
    remove_agent,
    save_agent,
)


class TestLoadAllAgents:
    def test_empty_when_file_missing(self, tmp_config_dir):
        """Returns {} when agents.yaml doesn't exist."""
        assert load_all_agents() == {}


class TestSaveAndLoadAgent:
    def test_round_trip(self, tmp_config_dir):
        """Save then load returns same data."""
        meta = {"template": "claude-code", "folder": "/tmp/proj"}
        save_agent("boris", meta)
        assert load_agent("boris") == meta

    def test_preserves_others(self, tmp_config_dir):
        """Saving boris doesn't clobber alice."""
        save_agent("alice", {"template": "t1", "folder": "/a"})
        save_agent("boris", {"template": "t2", "folder": "/b"})

        assert load_agent("alice") == {"template": "t1", "folder": "/a"}
        assert load_agent("boris") == {"template": "t2", "folder": "/b"}


class TestRemoveAgent:
    def test_remove_existing(self, tmp_config_dir):
        """Returns True when agent exists."""
        save_agent("boris", {"template": "t", "folder": "/f"})
        assert remove_agent("boris") is True
        assert load_agent("boris") == {}

    def test_remove_nonexistent(self, tmp_config_dir):
        """Returns False when agent doesn't exist."""
        assert remove_agent("ghost") is False


class TestMigrateFromJson:
    def test_creates_entry_and_deletes_json(self, tmp_config_dir):
        """Migration writes to agents.yaml and removes .safeyolo.json."""
        agent_dir = tmp_config_dir / "agents" / "boris"
        agent_dir.mkdir(parents=True)
        json_file = agent_dir / ".safeyolo.json"
        meta = {"template": "claude-code", "folder": "/tmp/proj"}
        json_file.write_text(json.dumps(meta))

        result = migrate_from_json("boris", agent_dir)

        assert result == meta
        assert load_agent("boris") == meta
        assert not json_file.exists()

    def test_preserves_existing_agents(self, tmp_config_dir):
        """Migration doesn't clobber other agents."""
        save_agent("alice", {"template": "t1", "folder": "/a"})

        agent_dir = tmp_config_dir / "agents" / "boris"
        agent_dir.mkdir(parents=True)
        json_file = agent_dir / ".safeyolo.json"
        json_file.write_text(json.dumps({"template": "t2", "folder": "/b"}))

        migrate_from_json("boris", agent_dir)

        assert load_agent("alice") == {"template": "t1", "folder": "/a"}
        assert load_agent("boris") == {"template": "t2", "folder": "/b"}

    def test_missing_json_returns_empty(self, tmp_config_dir):
        """Returns {} when .safeyolo.json doesn't exist."""
        agent_dir = tmp_config_dir / "agents" / "boris"
        agent_dir.mkdir(parents=True)

        assert migrate_from_json("boris", agent_dir) == {}
