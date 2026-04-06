"""Tests for agent port mapping features."""

from unittest.mock import patch

import pytest
import typer

from safeyolo.agents_store import load_agent, save_agent
from safeyolo.cli import app
from safeyolo.commands.agent import _parse_port, _parse_user_default_args


class TestParsePort:
    """Unit tests for _parse_port()."""

    def test_valid_two_part(self):
        """Two-part spec normalizes to 127.0.0.1 bind."""
        assert _parse_port("6080:6080") == "127.0.0.1:6080:6080"

    def test_valid_two_part_different_ports(self):
        """Different host and container ports."""
        assert _parse_port("8888:3000") == "127.0.0.1:8888:3000"

    def test_valid_three_part_localhost(self):
        """Three-part with 127.0.0.1 passes through."""
        assert _parse_port("127.0.0.1:6080:6080") == "127.0.0.1:6080:6080"

    def test_reject_non_localhost_bind(self):
        """Rejects non-localhost bind address."""
        with pytest.raises(typer.Exit):
            _parse_port("0.0.0.0:6080:6080")

    def test_reject_one_part(self):
        """Rejects single port (no colon)."""
        with pytest.raises(typer.Exit):
            _parse_port("6080")

    def test_reject_four_part(self):
        """Rejects too many colons."""
        with pytest.raises(typer.Exit):
            _parse_port("127.0.0.1:6080:6080:tcp")

    def test_reject_non_integer_host(self):
        """Rejects non-integer host port."""
        with pytest.raises(typer.Exit):
            _parse_port("abc:6080")

    def test_reject_non_integer_container(self):
        """Rejects non-integer container port."""
        with pytest.raises(typer.Exit):
            _parse_port("6080:abc")

    def test_reject_port_zero(self):
        """Rejects port 0."""
        with pytest.raises(typer.Exit):
            _parse_port("0:6080")

    def test_reject_port_over_65535(self):
        """Rejects port > 65535."""
        with pytest.raises(typer.Exit):
            _parse_port("6080:65536")

    def test_reject_reserved_container_port_8080(self):
        """Rejects reserved container port 8080 (proxy)."""
        with pytest.raises(typer.Exit):
            _parse_port("8080:8080")

    def test_reject_reserved_container_port_9090(self):
        """Rejects reserved container port 9090 (admin)."""
        with pytest.raises(typer.Exit):
            _parse_port("9090:9090")

    def test_allow_reserved_as_host_port(self):
        """Reserved ports are fine as host port (only container is checked)."""
        assert _parse_port("8080:3000") == "127.0.0.1:8080:3000"
        assert _parse_port("9090:3000") == "127.0.0.1:9090:3000"


def _setup_agent(config_dir, name="test-agent", template="claude-code", ports=None):
    """Helper to create a minimal agent directory with metadata in policy.toml."""
    agent_dir = config_dir / "agents" / name
    agent_dir.mkdir(parents=True, exist_ok=True)
    (agent_dir / "docker-compose.yml").write_text("version: '3'\n")
    metadata = {"template": template, "folder": "/tmp/project"}
    if ports:
        metadata["ports"] = ports
    save_agent(name, metadata)
    return agent_dir


class TestAgentConfigPorts:
    """CLI integration tests for port config operations."""

    def test_add_port_stores_in_metadata(self, cli_runner, tmp_config_dir):
        """--add-port stores normalized port in policy.toml."""
        _setup_agent(tmp_config_dir, "test-agent")
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--add-port", "6080:6080"])
        assert result.exit_code == 0
        assert "Added port" in result.output

        metadata = load_agent("test-agent")
        assert metadata["ports"] == ["127.0.0.1:6080:6080"]

    def test_add_port_deduplicates_by_container_port(self, cli_runner, tmp_config_dir):
        """Adding a port with same container port replaces existing."""
        _setup_agent(tmp_config_dir, "test-agent", ports=["127.0.0.1:6080:6080"])
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--add-port", "7070:6080"])
        assert result.exit_code == 0

        metadata = load_agent("test-agent")
        assert metadata["ports"] == ["127.0.0.1:7070:6080"]

    def test_remove_port_by_container_port(self, cli_runner, tmp_config_dir):
        """--remove-port removes matching container port."""
        _setup_agent(tmp_config_dir, "test-agent", ports=["127.0.0.1:6080:6080"])
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--remove-port", "6080"])
        assert result.exit_code == 0
        assert "Removed port" in result.output

        metadata = load_agent("test-agent")
        assert "ports" not in metadata

    def test_remove_port_warns_if_not_found(self, cli_runner, tmp_config_dir):
        """--remove-port warns when no match."""
        _setup_agent(tmp_config_dir, "test-agent")
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--remove-port", "9999"])
        assert result.exit_code == 0
        assert "No port mapping found" in result.output

    def test_clear_ports(self, cli_runner, tmp_config_dir):
        """--clear-ports removes all port mappings."""
        _setup_agent(tmp_config_dir, "test-agent", ports=["127.0.0.1:6080:6080", "127.0.0.1:8888:3000"])
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--clear-ports"])
        assert result.exit_code == 0
        assert "Cleared all ports" in result.output

        metadata = load_agent("test-agent")
        assert "ports" not in metadata

    def test_show_displays_ports(self, cli_runner, tmp_config_dir):
        """--show includes ports in table."""
        _setup_agent(tmp_config_dir, "test-agent", ports=["127.0.0.1:6080:6080"])
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--show"])
        assert result.exit_code == 0
        assert "6080" in result.output

    def test_show_displays_none_when_no_ports(self, cli_runner, tmp_config_dir):
        """--show shows 'none' when no ports configured."""
        _setup_agent(tmp_config_dir, "test-agent")
        result = cli_runner.invoke(app, ["agent", "config", "test-agent", "--show"])
        assert result.exit_code == 0
        assert "none" in result.output


class TestAgentRunPorts:
    """Tests for port flags in agent run command."""

    def test_port_flag_produces_dash_p(self, cli_runner, tmp_config_dir, mock_docker_running):
        """--port flag adds -p to docker command."""
        _setup_agent(tmp_config_dir, "test-agent")
        cli_runner.invoke(app, ["agent", "run", "test-agent", "--port", "6080:6080"])

        # Find the docker compose run call
        for call in mock_docker_running.call_args_list:
            args = call[0][0] if call[0] else call.kwargs.get("args", [])
            if "run" in args and "compose" in args:
                assert "-p" in args
                idx = args.index("-p")
                assert args[idx + 1] == "127.0.0.1:6080:6080"
                return
        pytest.fail("No docker compose run call found")

    def test_merges_metadata_and_transient_ports(self, cli_runner, tmp_config_dir, mock_docker_running):
        """Metadata ports and --port flags are both included."""
        _setup_agent(tmp_config_dir, "test-agent", ports=["127.0.0.1:6080:6080"])
        cli_runner.invoke(app, ["agent", "run", "test-agent", "--port", "8888:3000"])

        for call in mock_docker_running.call_args_list:
            args = call[0][0] if call[0] else call.kwargs.get("args", [])
            if "run" in args and "compose" in args:
                # Collect all -p values
                port_values = []
                for i, a in enumerate(args):
                    if a == "-p" and i + 1 < len(args):
                        port_values.append(args[i + 1])
                assert "127.0.0.1:6080:6080" in port_values
                assert "127.0.0.1:8888:3000" in port_values
                return
        pytest.fail("No docker compose run call found")


class TestAgentAddPorts:
    """Tests for --port in agent add command."""

    def test_port_stores_in_metadata(self, cli_runner, tmp_config_dir, mock_docker_running):
        """--port on agent add stores ports in policy.toml."""
        agent_dir = tmp_config_dir / "agents" / "test-add"

        def fake_render(**kwargs):
            agent_dir.mkdir(parents=True, exist_ok=True)
            compose_file = agent_dir / "docker-compose.yml"
            compose_file.write_text("version: '3'\n")
            return [str(compose_file)]

        with (
            patch("safeyolo.commands.agent.render_template", side_effect=fake_render),
            patch("safeyolo.commands.agent.get_agent_config"),
            patch("safeyolo.commands.agent._check_project_ownership"),
            patch("safeyolo.commands.agent._ensure_host_config"),
        ):
            # Create the folder the agent points to
            folder = tmp_config_dir / "project"
            folder.mkdir(exist_ok=True)

            result = cli_runner.invoke(
                app,
                [
                    "agent",
                    "add",
                    "test-add",
                    "claude-code",
                    str(folder),
                    "--port",
                    "6080:6080",
                    "--no-run",
                ],
            )
            assert result.exit_code == 0, result.output

            metadata = load_agent("test-add")
            assert metadata["ports"] == ["127.0.0.1:6080:6080"]


# ---------------------------------------------------------------------------
# _parse_user_default_args
# ---------------------------------------------------------------------------


class TestParseUserDefaultArgs:
    def test_none_returns_none(self):
        assert _parse_user_default_args(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_user_default_args("") is None

    def test_simple_args(self):
        assert _parse_user_default_args("--model opus --verbose") == ["--model", "opus", "--verbose"]

    def test_quoted_args(self):
        assert _parse_user_default_args('--prompt "hello world"') == ["--prompt", "hello world"]

    def test_single_arg(self):
        assert _parse_user_default_args("--verbose") == ["--verbose"]
