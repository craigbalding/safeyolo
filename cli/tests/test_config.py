"""Tests for config module."""

import yaml

from safeyolo.config import (
    DEFAULT_CONFIG,
    _deep_merge,
    ensure_directories,
    find_config_dir,
    get_admin_token,
    get_admin_token_path,
    get_agent_map_path,
    get_agent_token_path,
    get_agents_dir,
    get_certs_dir,
    get_config_dir,
    get_config_path,
    get_data_dir,
    get_logs_dir,
    get_policies_dir,
    get_policy_toml_path,
    get_proxy_pid_path,
    get_share_dir,
    get_ssh_key_path,
    get_vm_helper_path,
    load_config,
    save_config,
)


class TestFindConfigDir:
    """Tests for find_config_dir().

    Note: find_config_dir() returns CONFIG_DIR if it exists, None otherwise.
    It uses the fixed path ~/.safeyolo (no project-local search).
    """

    def test_returns_config_dir_if_exists(self, tmp_path, monkeypatch):
        """Returns config dir when directory exists."""
        config_dir = tmp_path / ".safeyolo"
        config_dir.mkdir()
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

        result = find_config_dir()
        assert result == config_dir

    def test_returns_none_if_missing(self, tmp_path, monkeypatch):
        """Returns None if config dir doesn't exist."""
        config_dir = tmp_path / ".safeyolo"  # Not created
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

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
        config_dir = tmp_path / ".safeyolo"
        config_dir.mkdir()
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
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
        config_dir = tmp_path / ".safeyolo"  # Not created yet
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
        config = {"version": 1}
        save_config(config)

        assert (config_dir / "config.yaml").exists()


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
        # Still need to isolate config dir to avoid reading real token file
        config_dir = tmp_path / ".safeyolo"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

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
        config_dir = tmp_path / ".safeyolo"
        config_dir.mkdir()
        (config_dir / "data").mkdir()
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

        result = get_admin_token()
        assert result is None


class TestGetLogsDir:
    """Tests for get_logs_dir()."""

    def test_get_logs_dir_default(self, tmp_path, monkeypatch):
        """Returns XDG_STATE_HOME/safeyolo when no override is set."""
        monkeypatch.delenv("SAFEYOLO_LOGS_DIR", raising=False)
        monkeypatch.delenv("XDG_STATE_HOME", raising=False)
        result = get_logs_dir()
        # Default: ~/.local/state/safeyolo
        from pathlib import Path

        expected = Path.home() / ".local" / "state" / "safeyolo"
        assert result == expected


class TestGetConfigPath:
    """Tests for path getters."""

    def test_get_config_path(self, tmp_config_dir):
        """Returns path to config.yaml."""
        path = get_config_path()
        assert path == tmp_config_dir / "config.yaml"

    def test_get_config_dir_creates(self, tmp_path, monkeypatch):
        """get_config_dir creates directory when create=True."""
        config_dir = tmp_path / ".safeyolo"  # Not created yet
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
        result = get_config_dir(create=True)
        assert result.exists()
        assert result == config_dir


class TestGetAdminTokenEdgeCases:
    """Additional tests for get_admin_token() edge cases."""

    def test_get_admin_token_strips_whitespace(self, tmp_config_dir, monkeypatch):
        """Token read from file has trailing whitespace/newlines stripped."""
        monkeypatch.delenv("SAFEYOLO_ADMIN_TOKEN", raising=False)
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("  my-token-123  \n\n")
        result = get_admin_token()
        assert result == "my-token-123"

    def test_get_admin_token_env_overrides_file(self, tmp_config_dir, monkeypatch):
        """Environment variable takes precedence even when file has different value."""
        monkeypatch.setenv("SAFEYOLO_ADMIN_TOKEN", "from-env")
        token_path = tmp_config_dir / "data" / "admin_token"
        token_path.write_text("from-file")
        result = get_admin_token()
        assert result == "from-env"


# =============================================================================
# Path helpers (pre-existing, previously untested)
# =============================================================================


class TestPathHelpers:
    """Tests for path-building functions under config_dir."""

    def test_get_certs_dir(self, tmp_config_dir):
        """Returns certs/ under config dir."""
        assert get_certs_dir() == tmp_config_dir / "certs"

    def test_get_policies_dir(self, tmp_config_dir):
        """Returns policies/ under config dir."""
        assert get_policies_dir() == tmp_config_dir / "policies"

    def test_get_data_dir(self, tmp_config_dir):
        """Returns data/ under config dir."""
        assert get_data_dir() == tmp_config_dir / "data"

    def test_get_agents_dir(self, tmp_config_dir):
        """Returns agents/ under config dir."""
        assert get_agents_dir() == tmp_config_dir / "agents"

    def test_get_policy_toml_path(self, tmp_config_dir):
        """Returns policy.toml under config dir."""
        assert get_policy_toml_path() == tmp_config_dir / "policy.toml"

    def test_get_admin_token_path(self, tmp_config_dir):
        """Returns data/admin_token under config dir."""
        assert get_admin_token_path() == tmp_config_dir / "data" / "admin_token"

    def test_get_agent_token_path(self, tmp_config_dir):
        """Returns data/agent_token under config dir."""
        assert get_agent_token_path() == tmp_config_dir / "data" / "agent_token"


# =============================================================================
# VM-specific path helpers (new on microvm branch)
# =============================================================================


class TestVMPathHelpers:
    """Tests for VM-specific path functions added on the microvm branch."""

    def test_get_share_dir(self, tmp_config_dir):
        """Returns share/ under config dir for VM assets."""
        assert get_share_dir() == tmp_config_dir / "share"

    def test_get_vm_helper_path(self, tmp_config_dir):
        """Returns bin/safeyolo-vm under config dir."""
        assert get_vm_helper_path() == tmp_config_dir / "bin" / "safeyolo-vm"

    def test_get_ssh_key_path(self, tmp_config_dir):
        """Returns data/vm_ssh_key under config dir."""
        assert get_ssh_key_path() == tmp_config_dir / "data" / "vm_ssh_key"

    def test_get_agent_map_path(self, tmp_config_dir):
        """Returns data/agent_map.json under config dir."""
        assert get_agent_map_path() == tmp_config_dir / "data" / "agent_map.json"

    def test_get_proxy_pid_path(self, tmp_config_dir):
        """Returns data/proxy.pid under config dir."""
        assert get_proxy_pid_path() == tmp_config_dir / "data" / "proxy.pid"

    def test_all_vm_paths_respect_config_dir_override(self, tmp_path, monkeypatch):
        """All VM path helpers use the overridden config dir, not the real home."""
        custom = tmp_path / "custom-safeyolo"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(custom))

        assert get_share_dir() == custom / "share"
        assert get_vm_helper_path() == custom / "bin" / "safeyolo-vm"
        assert get_ssh_key_path() == custom / "data" / "vm_ssh_key"
        assert get_agent_map_path() == custom / "data" / "agent_map.json"
        assert get_proxy_pid_path() == custom / "data" / "proxy.pid"


# =============================================================================
# ensure_directories()
# =============================================================================


class TestEnsureDirectories:
    """Tests for ensure_directories()."""

    def test_creates_all_required_subdirectories(self, tmp_path, monkeypatch):
        """Creates config dir and all required subdirectories."""
        config_dir = tmp_path / ".safeyolo"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

        ensure_directories()

        assert config_dir.is_dir()
        assert (config_dir / "certs").is_dir()
        assert (config_dir / "policies").is_dir()
        assert (config_dir / "data").is_dir()
        assert (config_dir / "logs").is_dir()
        assert (config_dir / "share").is_dir()
        assert (config_dir / "bin").is_dir()

    def test_idempotent_when_dirs_already_exist(self, tmp_path, monkeypatch):
        """Calling ensure_directories twice does not raise."""
        config_dir = tmp_path / ".safeyolo"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

        ensure_directories()
        # Put a file in one of the dirs to verify it survives a second call
        marker = config_dir / "data" / "marker.txt"
        marker.write_text("keep me")

        ensure_directories()

        assert marker.read_text() == "keep me"

    def test_creates_exactly_six_subdirectories(self, tmp_path, monkeypatch):
        """Creates exactly the expected set of subdirectories, no more."""
        config_dir = tmp_path / ".safeyolo"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

        ensure_directories()

        subdirs = {p.name for p in config_dir.iterdir() if p.is_dir()}
        assert subdirs == {"certs", "policies", "data", "logs", "share", "bin"}
