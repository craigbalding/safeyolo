"""Tests for agent template loading and rendering.

Tests the TOML config loader, template management, and real agent.toml validation.
"""

import os
from pathlib import Path

import pytest

from safeyolo.templates import (
    TemplateError,
    detect_host_config_for_agent,
    get_agent_config,
    get_available_templates,
)
from safeyolo.templates.loader import (
    AgentConfig,
    AgentConfigError,
    AuthConfig,
    VMConfig,
    HostConfig,
    InstallConfig,
    InstructionsConfig,
    RunConfig,
    load_agent_config,
)

# =============================================================================
# loader.py - TOML Config Loader Tests
# =============================================================================


class TestLoadAgentConfig:
    """Tests for load_agent_config()."""

    def test_loads_valid_toml(self, tmp_path):
        """Successfully loads a valid agent.toml file."""
        agent_dir = tmp_path / "test-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
schema_version = 1

[agent]
name = "test-agent"
description = "Test agent for unit tests"

[install]
mise = "npm:test-package"
binary = "test-bin"

[run]
command = "test-bin"
args = ["--verbose"]
auto_args = ["--auto-mode"]

[auth]
env_var = "TEST_API_KEY"
oauth_file = ".test/auth.json"
setup_hint = "Set TEST_API_KEY"

[host]
config_dirs = [".test"]
config_files = [".testrc"]

[vm]
env = { TEST_VAR = "value" }

[instructions]
content = "Test instructions"

[instructions.injection]
type = "system_file"
path = "/etc/test/config.md"
""")

        config = load_agent_config(agent_dir)

        assert config.name == "test-agent"
        assert config.description == "Test agent for unit tests"
        assert config.install.mise == "npm:test-package"
        assert config.install.binary == "test-bin"
        assert config.run.command == "test-bin"
        assert config.run.args == ["--verbose"]
        assert config.run.auto_args == ["--auto-mode"]
        assert config.auth.env_var == "TEST_API_KEY"
        assert config.auth.oauth_file == ".test/auth.json"
        assert config.host.config_dirs == [".test"]
        assert config.host.config_files == [".testrc"]
        assert config.vm.env == {"TEST_VAR": "value"}
        assert config.instructions.content == "Test instructions"
        assert config.instructions.injection_type == "system_file"
        assert config.instructions.path == "/etc/test/config.md"

    def test_raises_on_missing_file(self, tmp_path):
        """Raises AgentConfigError when agent.toml doesn't exist."""
        agent_dir = tmp_path / "missing-agent"
        agent_dir.mkdir()

        with pytest.raises(AgentConfigError, match="agent.toml not found"):
            load_agent_config(agent_dir)

    def test_raises_on_invalid_toml(self, tmp_path):
        """Raises AgentConfigError on invalid TOML syntax."""
        agent_dir = tmp_path / "invalid-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent
name = "broken"
""")

        with pytest.raises(AgentConfigError, match="Invalid TOML"):
            load_agent_config(agent_dir)

    def test_raises_on_future_schema_version(self, tmp_path):
        """Raises AgentConfigError when schema version is too new."""
        agent_dir = tmp_path / "future-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
schema_version = 999

[agent]
name = "future"
""")

        with pytest.raises(AgentConfigError, match="schema version 999 is newer"):
            load_agent_config(agent_dir)

    def test_uses_defaults_for_missing_sections(self, tmp_path):
        """Uses defaults when optional sections are missing."""
        agent_dir = tmp_path / "minimal-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
name = "minimal"
""")

        config = load_agent_config(agent_dir)

        assert config.name == "minimal"
        assert config.description == ""
        assert config.install.mise == ""
        assert config.install.binary == ""
        assert config.run.command == ""
        assert config.run.args == []
        assert config.run.auto_args == []
        assert config.auth.env_var == ""
        assert config.host.config_dirs == []
        assert config.host.config_files == []
        assert config.vm.cpus == 4
        assert config.vm.memory == 4096
        assert config.vm.disk_size == 4096
        assert config.vm.env == {}
        assert config.instructions.content == ""

    def test_uses_dirname_when_name_missing(self, tmp_path):
        """Falls back to directory name when agent name is missing."""
        agent_dir = tmp_path / "dirname-fallback"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
description = "No name specified"
""")

        config = load_agent_config(agent_dir)
        assert config.name == "dirname-fallback"

    def test_vm_section_populates_all_fields(self, tmp_path):
        """Reads cpus, memory, disk_size, env from [vm] section."""
        agent_dir = tmp_path / "vm-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
name = "vm-test"

[vm]
cpus = 8
memory = 8192
disk_size = 16384
env = { GPU = "true", WORKERS = "4" }
""")

        config = load_agent_config(agent_dir)
        assert config.vm.cpus == 8
        assert config.vm.memory == 8192
        assert config.vm.disk_size == 16384
        assert config.vm.env == {"GPU": "true", "WORKERS": "4"}

    def test_docker_section_falls_back_to_vm(self, tmp_path):
        """[docker] section is read when [vm] is absent (migration path)."""
        agent_dir = tmp_path / "legacy-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
name = "legacy"

[docker]
cpus = 2
memory = 2048
env = { LEGACY = "yes" }
""")

        config = load_agent_config(agent_dir)
        assert config.vm.cpus == 2
        assert config.vm.memory == 2048
        assert config.vm.env == {"LEGACY": "yes"}

    def test_vm_section_takes_precedence_over_docker(self, tmp_path):
        """When both [vm] and [docker] exist, [vm] wins."""
        agent_dir = tmp_path / "both-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
name = "both"

[docker]
cpus = 2
memory = 2048
env = { FROM = "docker" }

[vm]
cpus = 8
memory = 8192
env = { FROM = "vm" }
""")

        config = load_agent_config(agent_dir)
        assert config.vm.cpus == 8
        assert config.vm.memory == 8192
        assert config.vm.env == {"FROM": "vm"}

    def test_vm_defaults_when_neither_section_present(self, tmp_path):
        """VMConfig uses dataclass defaults when no [vm] or [docker] section."""
        agent_dir = tmp_path / "no-vm-agent"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
name = "no-vm"
""")

        config = load_agent_config(agent_dir)
        assert config.vm.cpus == 4
        assert config.vm.memory == 4096
        assert config.vm.disk_size == 4096
        assert config.vm.env == {}

    def test_vm_partial_fields_get_defaults(self, tmp_path):
        """Missing fields in [vm] section get defaults."""
        agent_dir = tmp_path / "partial-vm"
        agent_dir.mkdir()
        (agent_dir / "agent.toml").write_text("""
[agent]
name = "partial"

[vm]
cpus = 2
""")

        config = load_agent_config(agent_dir)
        assert config.vm.cpus == 2
        assert config.vm.memory == 4096
        assert config.vm.disk_size == 4096
        assert config.vm.env == {}


class TestRunConfig:
    """Tests for RunConfig dataclass properties."""

    def test_full_command_with_args(self):
        """full_command joins command and args."""
        run = RunConfig(command="test", args=["--flag", "value"], auto_args=[])
        assert run.full_command == "test --flag value"

    def test_full_command_without_args(self):
        """full_command returns just command when no args."""
        run = RunConfig(command="test", args=[], auto_args=[])
        assert run.full_command == "test"

    def test_auto_args_str(self):
        """auto_args_str joins auto_args with spaces."""
        run = RunConfig(command="test", args=[], auto_args=["--auto", "--yes"])
        assert run.auto_args_str == "--auto --yes"

    def test_auto_args_str_empty(self):
        """auto_args_str returns empty string when no auto_args."""
        run = RunConfig(command="test", args=[], auto_args=[])
        assert run.auto_args_str == ""


# =============================================================================
# templates/__init__.py - Template Management Tests
# =============================================================================


class TestGetAvailableTemplates:
    """Tests for get_available_templates()."""

    def test_returns_dict_of_templates(self):
        """Returns dict mapping template name to description."""
        templates = get_available_templates()

        assert isinstance(templates, dict)
        assert len(templates) >= 2  # claude-code and openai-codex at minimum
        assert "claude-code" in templates
        assert "openai-codex" in templates

    def test_returns_exact_known_templates(self):
        """Returns exactly the set of known templates (no surprise additions)."""
        templates = get_available_templates()
        assert set(templates.keys()) == {"claude-code", "openai-codex"}

    def test_descriptions_are_non_empty(self):
        """All templates have non-empty descriptions."""
        templates = get_available_templates()

        for name, description in templates.items():
            assert description, f"Template {name} has empty description"

    def test_content_file_loading(self):
        """Templates with content_file load instructions from the referenced file.

        claude-code uses content_file = "instructions.md". The loaded config must
        have non-empty instructions.content populated from that file, not from an
        inline content field.
        """
        config = get_agent_config("claude-code")
        assert config.instructions.content, "instructions.content should be loaded from content_file"
        # The instructions.md file contains SafeYolo-specific content
        assert "SafeYolo" in config.instructions.content or "safeyolo" in config.instructions.content.lower()


class TestGetAgentConfig:
    """Tests for get_agent_config()."""

    def test_returns_config_for_valid_template(self):
        """Returns AgentConfig for a valid template name."""
        config = get_agent_config("claude-code")

        assert isinstance(config, AgentConfig)
        assert config.name == "claude-code"
        assert config.install.binary == "claude"

    def test_raises_on_unknown_template(self):
        """Raises TemplateError for unknown template name."""
        with pytest.raises(TemplateError, match="Unknown template"):
            get_agent_config("nonexistent-agent")

    def test_error_includes_available_templates(self):
        """Error message lists available templates."""
        with pytest.raises(TemplateError) as exc_info:
            get_agent_config("bad-name")

        assert "claude-code" in str(exc_info.value)


class TestDetectHostConfigForAgent:
    """Tests for detect_host_config_for_agent().

    Returns a list of config_dirs names that exist under $HOME.
    """

    def test_returns_existing_dirs(self, tmp_path, monkeypatch):
        """Returns names of config_dirs that exist under home."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".test-config").mkdir()
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        config = AgentConfig(
            name="test",
            description="",
            install=InstallConfig(mise="", binary=""),
            run=RunConfig(command="", args=[], auto_args=[]),
            auth=AuthConfig(env_var="", oauth_file="", setup_hint=""),
            host=HostConfig(config_dirs=[".test-config", ".missing"], config_files=[]),
            vm=VMConfig(),
            instructions=InstructionsConfig(),
        )

        found = detect_host_config_for_agent(config)

        assert found == [".test-config"]

    def test_excludes_missing_dirs(self, tmp_path, monkeypatch):
        """Dirs that do not exist are not in the returned list."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        config = AgentConfig(
            name="test",
            description="",
            install=InstallConfig(mise="", binary=""),
            run=RunConfig(command="", args=[], auto_args=[]),
            auth=AuthConfig(env_var="", oauth_file="", setup_hint=""),
            host=HostConfig(config_dirs=[".no-such-dir"], config_files=[]),
            vm=VMConfig(),
            instructions=InstructionsConfig(),
        )

        found = detect_host_config_for_agent(config)

        assert found == []

    def test_returns_empty_list_when_no_dirs_configured(self, tmp_path, monkeypatch):
        """Returns empty list when agent has no config_dirs."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        config = AgentConfig(
            name="test",
            description="",
            install=InstallConfig(mise="", binary=""),
            run=RunConfig(command="", args=[], auto_args=[]),
            auth=AuthConfig(env_var="", oauth_file="", setup_hint=""),
            host=HostConfig(config_dirs=[], config_files=[]),
            vm=VMConfig(),
            instructions=InstructionsConfig(),
        )

        found = detect_host_config_for_agent(config)

        assert found == []

    def test_does_not_match_files_as_dirs(self, tmp_path, monkeypatch):
        """A file with the same name as a config_dir is not returned (only dirs count)."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".is-a-file").write_text("not a directory")
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        config = AgentConfig(
            name="test",
            description="",
            install=InstallConfig(mise="", binary=""),
            run=RunConfig(command="", args=[], auto_args=[]),
            auth=AuthConfig(env_var="", oauth_file="", setup_hint=""),
            host=HostConfig(config_dirs=[".is-a-file"], config_files=[]),
            vm=VMConfig(),
            instructions=InstructionsConfig(),
        )

        found = detect_host_config_for_agent(config)

        assert found == []


# =============================================================================
# Real Agent.toml Validation Tests
# =============================================================================


class TestRealAgentTomlFiles:
    """Tests validating the actual agent.toml files in the repo."""

    def test_claude_code_toml_parses(self):
        """claude-code agent.toml parses successfully."""
        config = get_agent_config("claude-code")

        assert config.name == "claude-code"
        assert config.schema_version == 1

    def test_openai_codex_toml_parses(self):
        """openai-codex agent.toml parses successfully."""
        config = get_agent_config("openai-codex")

        assert config.name == "openai-codex"
        assert config.schema_version == 1

    def test_claude_code_has_required_fields(self):
        """claude-code has all required fields populated."""
        config = get_agent_config("claude-code")

        # Install
        assert config.install.mise, "mise package not specified"
        assert config.install.binary, "binary not specified"

        # Run
        assert config.run.command, "run command not specified"

        # Auth
        assert config.auth.env_var, "auth env_var not specified"
        assert config.auth.setup_hint, "setup_hint not specified"

        # Instructions
        assert config.instructions.content, "instructions content empty"

    def test_openai_codex_has_required_fields(self):
        """openai-codex has all required fields populated."""
        config = get_agent_config("openai-codex")

        assert config.install.mise, "mise package not specified"
        assert config.install.binary, "binary not specified"
        assert config.run.command, "run command not specified"
        assert config.auth.env_var, "auth env_var not specified"

    def test_claude_code_injection_type_valid(self):
        """claude-code uses valid injection type."""
        config = get_agent_config("claude-code")

        assert config.instructions.injection_type in ("system_file", "cli_arg")
        if config.instructions.injection_type == "system_file":
            assert config.instructions.path, "system_file injection needs path"

    def test_openai_codex_injection_type_valid(self):
        """openai-codex uses valid injection type."""
        config = get_agent_config("openai-codex")

        assert config.instructions.injection_type in ("system_file", "cli_arg")
        if config.instructions.injection_type == "cli_arg":
            assert config.instructions.arg_name, "cli_arg injection needs arg_name"

    def test_all_templates_have_descriptions(self):
        """All registered templates have descriptions."""
        templates = get_available_templates()

        for name, description in templates.items():
            assert description, f"Template '{name}' missing description"
            assert len(description) > 10, f"Template '{name}' description too short"

    def test_auto_args_are_valid_cli_flags(self):
        """auto_args should be valid CLI flag format (start with -)."""
        for template_name in get_available_templates():
            config = get_agent_config(template_name)

            for arg in config.run.auto_args:
                assert arg.startswith("-"), f"{template_name}: auto_arg '{arg}' should be a CLI flag (start with -)"
                # Flags shouldn't be empty or just dashes
                assert len(arg.strip("-")) > 0, f"{template_name}: auto_arg '{arg}' is empty"
