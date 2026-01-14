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
    render_template,
)
from safeyolo.templates.loader import (
    AgentConfig,
    AgentConfigError,
    AuthConfig,
    DockerConfig,
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

[docker]
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
        assert config.docker.env == {"TEST_VAR": "value"}
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
        assert config.docker.env == {}
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

    def test_descriptions_are_non_empty(self):
        """All templates have non-empty descriptions."""
        templates = get_available_templates()

        for name, description in templates.items():
            assert description, f"Template {name} has empty description"


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
    """Tests for detect_host_config_for_agent()."""

    def test_finds_existing_dirs(self, tmp_path, monkeypatch):
        """Detects existing host config directories."""
        # Create fake home with config dir
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".test-config").mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        config = AgentConfig(
            name="test",
            description="",
            install=InstallConfig(mise="", binary=""),
            run=RunConfig(command="", args=[], auto_args=[]),
            auth=AuthConfig(env_var="", oauth_file="", setup_hint=""),
            host=HostConfig(config_dirs=[".test-config", ".missing"], config_files=[]),
            docker=DockerConfig(),
            instructions=InstructionsConfig(),
        )

        status = detect_host_config_for_agent(config)

        assert ".test-config" in status.found_dirs
        assert ".missing" not in status.found_dirs

    def test_finds_existing_files(self, tmp_path, monkeypatch):
        """Detects existing host config files."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        (fake_home / ".testrc").write_text("config")
        monkeypatch.setattr(Path, "home", lambda: fake_home)

        config = AgentConfig(
            name="test",
            description="",
            install=InstallConfig(mise="", binary=""),
            run=RunConfig(command="", args=[], auto_args=[]),
            auth=AuthConfig(env_var="", oauth_file="", setup_hint=""),
            host=HostConfig(config_dirs=[], config_files=[".testrc", ".missingrc"]),
            docker=DockerConfig(),
            instructions=InstructionsConfig(),
        )

        status = detect_host_config_for_agent(config)

        assert ".testrc" in status.found_files
        assert ".missingrc" not in status.found_files

    def test_handles_empty_host_config(self, tmp_path, monkeypatch):
        """Returns empty status when no host config specified."""
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
            docker=DockerConfig(),
            instructions=InstructionsConfig(),
        )

        status = detect_host_config_for_agent(config)

        assert status.found_dirs == []
        assert status.found_files == []


class TestRenderTemplate:
    """Tests for render_template()."""

    def test_creates_env_file(self, tmp_config_dir, tmp_path):
        """Creates .env file with UID/GID and project info."""
        output_dir = tmp_path / "output"
        project_dir = "/home/user/myproject"

        files = render_template("claude-code", output_dir, project_dir)

        env_path = output_dir / ".env"
        assert env_path.exists()
        assert env_path in files

        content = env_path.read_text()
        assert f"SAFEYOLO_UID={os.getuid()}" in content
        assert f"SAFEYOLO_GID={os.getgid()}" in content
        assert f"USER_DIR={project_dir}" in content
        assert "USER_DIRNAME=myproject" in content

    def test_creates_compose_file(self, tmp_config_dir, tmp_path):
        """Creates docker-compose.yml from template."""
        output_dir = tmp_path / "output"

        files = render_template("claude-code", output_dir, "/tmp/project")

        compose_path = output_dir / "docker-compose.yml"
        assert compose_path.exists()
        assert compose_path in files

    def test_skips_agent_toml(self, tmp_config_dir, tmp_path):
        """Does not copy agent.toml to output."""
        output_dir = tmp_path / "output"

        render_template("claude-code", output_dir, "/tmp/project")

        assert not (output_dir / "agent.toml").exists()

    def test_accepts_instance_name_parameter(self, tmp_config_dir, tmp_path):
        """Accepts instance_name parameter without error.

        Note: instance_name is passed to template context but current templates
        use agent_name for service naming. This test verifies the parameter
        is accepted and rendering succeeds.
        """
        output_dir = tmp_path / "output"

        # Should not raise
        files = render_template("claude-code", output_dir, "/tmp/project", instance_name="myinstance")

        # Files should be created
        assert len(files) >= 2  # At least .env and docker-compose.yml
        assert (output_dir / "docker-compose.yml").exists()

    def test_raises_on_unknown_template(self, tmp_config_dir, tmp_path):
        """Raises TemplateError for unknown template."""
        output_dir = tmp_path / "output"

        with pytest.raises(TemplateError, match="Unknown template"):
            render_template("nonexistent", output_dir, "/tmp/project")

    def test_populates_template_variables(self, tmp_config_dir, tmp_path):
        """Template variables are correctly populated in output."""
        output_dir = tmp_path / "output"

        render_template("claude-code", output_dir, "/tmp/myproject")

        compose_content = (output_dir / "docker-compose.yml").read_text()

        # Should not contain raw Jinja2 placeholders
        assert "{{" not in compose_content, "Unrendered Jinja2 variable found"
        assert "}}" not in compose_content, "Unrendered Jinja2 variable found"
        assert "{%" not in compose_content, "Unrendered Jinja2 block found"

        # Verify specific substitutions happened
        assert "HTTP_PROXY=http://safeyolo:8080" in compose_content, \
            "proxy_hostname not substituted"
        assert "claude-code:" in compose_content, \
            "instance_name not substituted in service definition"


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
                assert arg.startswith("-"), \
                    f"{template_name}: auto_arg '{arg}' should be a CLI flag (start with -)"
                # Flags shouldn't be empty or just dashes
                assert len(arg.strip("-")) > 0, \
                    f"{template_name}: auto_arg '{arg}' is empty"
