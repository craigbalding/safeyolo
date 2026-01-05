"""Tests for config module."""

import os
from pathlib import Path

import pytest
import yaml

from safeyolo.config import (
    DEFAULT_CONFIG,
    _deep_merge,
    find_config_dir,
    get_admin_token,
    get_config_dir,
    get_config_path,
    load_config,
    save_config,
)


class TestFindConfigDir:
    """Tests for find_config_dir()."""

    def test_finds_project_dir(self, tmp_path, monkeypatch):
        """Finds ./safeyolo/ directory."""
        config_dir = tmp_path / "safeyolo"
        config_dir.mkdir()
        monkeypatch.chdir(tmp_path)

        result = find_config_dir()
        assert result == config_dir

    def test_finds_global_dir(self, tmp_path, monkeypatch):
        """Finds ~/.safeyolo/ directory."""
        global_dir = tmp_path / ".safeyolo"
        global_dir.mkdir()
        other_dir = tmp_path / "some_other_dir"
        other_dir.mkdir()
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(other_dir)

        result = find_config_dir()
        assert result == global_dir

    def test_prefers_project_over_global(self, tmp_path, monkeypatch):
        """Prefers ./safeyolo/ over ~/.safeyolo/."""
        project_dir = tmp_path / "safeyolo"
        project_dir.mkdir()
        global_dir = tmp_path / ".safeyolo"
        global_dir.mkdir()
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        result = find_config_dir()
        assert result == project_dir

    def test_returns_none_if_missing(self, tmp_path, monkeypatch):
        """Returns None if no config directory exists."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))

        result = find_config_dir()
        assert result is None


class TestLoadConfig:
    """Tests for load_config()."""

    def test_loads_valid_yaml(self, tmp_config_dir):
        """Loads config from YAML file."""
        config = load_config()
        assert config["proxy"]["port"] == 8080
        assert config["proxy"]["admin_port"] == 9090

    def test_returns_defaults_if_missing(self, tmp_path, monkeypatch):
        """Returns DEFAULT_CONFIG if no config file."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        config = load_config()
        assert config == DEFAULT_CONFIG

    def test_merges_with_defaults(self, tmp_config_dir):
        """Merges user config with defaults."""
        config = load_config()
        # User config has port, but should have all default keys
        assert "modes" in config
        assert config["modes"]["credential_guard"] == "block"

    def test_handles_empty_file(self, tmp_config_dir):
        """Handles empty config file."""
        (tmp_config_dir / "config.yaml").write_text("")
        config = load_config()
        assert config == DEFAULT_CONFIG


class TestSaveConfig:
    """Tests for save_config()."""

    def test_writes_yaml(self, tmp_config_dir):
        """Saves config to YAML file."""
        config = {"proxy": {"port": 9999}}
        save_config(config)

        content = (tmp_config_dir / "config.yaml").read_text()
        loaded = yaml.safe_load(content)
        assert loaded["proxy"]["port"] == 9999

    def test_creates_parent_dirs(self, tmp_path, monkeypatch):
        """Creates parent directories if needed."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        config = {"version": 1}
        save_config(config)

        # Default is now ~/.safeyolo/
        assert (tmp_path / ".safeyolo" / "config.yaml").exists()


class TestDeepMerge:
    """Tests for _deep_merge()."""

    def test_merges_flat_dicts(self):
        """Merges flat dictionaries."""
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        _deep_merge(base, override)
        assert base == {"a": 1, "b": 3, "c": 4}

    def test_merges_nested_dicts(self):
        """Recursively merges nested dictionaries."""
        base = {"outer": {"a": 1, "b": 2}}
        override = {"outer": {"b": 3}}
        _deep_merge(base, override)
        assert base == {"outer": {"a": 1, "b": 3}}

    def test_override_replaces_non_dict(self):
        """Override replaces non-dict values."""
        base = {"key": {"nested": 1}}
        override = {"key": "string_value"}
        _deep_merge(base, override)
        assert base == {"key": "string_value"}


class TestGetAdminToken:
    """Tests for get_admin_token()."""

    def test_from_env_var(self, monkeypatch, tmp_path):
        """Returns token from environment variable."""
        monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", "env-token-123")
        monkeypatch.chdir(tmp_path)

        result = get_admin_token()
        assert result == "env-token-123"

    def test_from_file(self, tmp_config_dir, monkeypatch):
        """Returns token from file."""
        monkeypatch.delenv("SAFEYOLO_ADMIN_TOKEN", raising=False)
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("file-token-456\n")

        result = get_admin_token()
        assert result == "file-token-456"

    def test_env_takes_precedence(self, tmp_config_dir, monkeypatch):
        """Environment variable takes precedence over file."""
        monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", "env-token")
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("file-token")

        result = get_admin_token()
        assert result == "env-token"

    def test_returns_none_if_missing(self, tmp_path, monkeypatch):
        """Returns None if no token configured."""
        monkeypatch.delenv("SAFEYOLO_ADMIN_TOKEN", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))

        result = get_admin_token()
        assert result is None


class TestGetConfigPath:
    """Tests for path getters."""

    def test_get_config_path(self, tmp_config_dir):
        """Returns path to config.yaml."""
        path = get_config_path()
        assert path == tmp_config_dir / "config.yaml"

    def test_get_config_dir_creates(self, tmp_path, monkeypatch):
        """get_config_dir creates directory when create=True."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("HOME", str(tmp_path))
        config_dir = get_config_dir(create=True)
        assert config_dir.exists()
        # Default is now ~/.safeyolo/
        assert config_dir.name == ".safeyolo"
