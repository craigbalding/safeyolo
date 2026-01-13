"""Integration tests for CLI lifecycle commands with service discovery.

Tests the full lifecycle:
1. safeyolo start - verify services.yaml created
2. safeyolo agent run - verify IP registered
3. safeyolo status - verify mapping shown as valid
4. safeyolo sync - verify regeneration works
5. safeyolo stop - verify services.yaml marked stale
"""

import json
import subprocess

import pytest
import yaml
from typer.testing import CliRunner


@pytest.fixture
def cli_runner():
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_safeyolo_env(tmp_path, monkeypatch):
    """Set up a complete safeyolo environment for integration tests."""
    # Create config directory structure
    config_dir = tmp_path / "safeyolo"
    config_dir.mkdir()
    (config_dir / "logs").mkdir()
    (config_dir / "certs").mkdir()
    (config_dir / "policies").mkdir()
    (config_dir / "data").mkdir()
    (config_dir / "agents").mkdir()

    # Write minimal config
    (config_dir / "config.yaml").write_text(
        "version: 1\n"
        "sandbox: true\n"
        "proxy:\n"
        "  port: 8080\n"
        "  admin_port: 9090\n"
        "  container_name: safeyolo-test\n"
        "  image: safeyolo:test\n"
    )

    # Change to parent so find_config_dir() finds ./safeyolo/
    monkeypatch.chdir(tmp_path)
    return config_dir


@pytest.fixture
def mock_docker_network_inspect(monkeypatch):
    """Mock docker network inspect to return container IPs."""
    def create_mock(containers: dict[str, str]):
        """Create mock that returns specified containers."""
        mock_output = json.dumps([{
            "Name": "safeyolo_internal",
            "Containers": {
                f"id-{name}": {"Name": name, "IPv4Address": f"{ip}/16"}
                for name, ip in containers.items()
            }
        }])

        def mock_run(args, **kwargs):
            if args[:3] == ["docker", "network", "inspect"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=0, stdout=mock_output, stderr=""
                )
            # Default pass-through for other docker commands
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="", stderr=""
            )

        return mock_run

    return create_mock


class TestLifecycleStart:
    """Tests for safeyolo start with service discovery."""

    def test_start_creates_services_yaml(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify start creates services.yaml from Docker network."""
        from safeyolo.cli import app

        # Track state: initially not running, then running after compose up
        started = {"value": False}

        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "version"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="Docker 24.0", stderr="")

            if args[:2] == ["docker", "ps"]:
                # Initially not running, then running after compose up
                if started["value"]:
                    return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")
                else:
                    return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            if args[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
                )

            if args[:3] == ["docker", "network", "inspect"]:
                mock_output = json.dumps([{
                    "Name": "safeyolo_internal",
                    "Containers": {
                        "proxy-id": {"Name": "safeyolo", "IPv4Address": "172.20.0.2/16"},
                        "agent-id": {"Name": "claude-code", "IPv4Address": "172.20.0.3/16"},
                    }
                }])
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=mock_output, stderr="")

            if "compose" in args and "up" in args:
                started["value"] = True
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            if "compose" in args:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = cli_runner.invoke(app, ["start", "--no-wait"])

        # Check services.yaml was created
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        assert services_path.exists(), f"services.yaml not created. Output: {result.output}"

        content = yaml.safe_load(services_path.read_text())
        assert "services" in content
        assert "claude-code" in content["services"]
        assert content["services"]["claude-code"]["ip"] == "172.20.0.3"


class TestLifecycleStop:
    """Tests for safeyolo stop with service discovery."""

    def test_stop_marks_services_stale(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify stop marks services.yaml as stale."""
        from safeyolo.cli import app

        # Create existing services.yaml
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        services_path.write_text("""
services:
  claude-code:
    ip: 172.20.0.3
    project: claude-code
""")

        # Mock docker commands
        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")
            if "compose" in args:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        cli_runner.invoke(app, ["stop"])

        # Check services.yaml is marked stale
        content = services_path.read_text()
        assert "stale" in content.lower()
        assert "safeyolo stopped" in content.lower()

        config = yaml.safe_load(content)
        assert config["services"] == {}


class TestLifecycleSync:
    """Tests for safeyolo sync command."""

    def test_sync_regenerates_services(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify sync regenerates services.yaml from Docker."""
        from safeyolo.cli import app

        # Create stale services.yaml
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        services_path.write_text("# stale\nservices: {}")

        # Mock docker commands
        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")

            if args[:3] == ["docker", "network", "inspect"]:
                mock_output = json.dumps([{
                    "Name": "safeyolo_internal",
                    "Containers": {
                        "proxy-id": {"Name": "safeyolo", "IPv4Address": "172.20.0.2/16"},
                        "agent-id": {"Name": "openai-codex", "IPv4Address": "172.20.0.4/16"},
                    }
                }])
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=mock_output, stderr="")

            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = cli_runner.invoke(app, ["sync"])

        assert "Synchronized" in result.output or "service" in result.output.lower()

        # Check services.yaml was regenerated
        content = yaml.safe_load(services_path.read_text())
        assert "openai-codex" in content["services"]
        assert content["services"]["openai-codex"]["ip"] == "172.20.0.4"

    def test_sync_fails_when_not_running(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify sync fails when SafeYolo is not running."""
        from safeyolo.cli import app

        # Mock docker ps returning empty (not running)
        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = cli_runner.invoke(app, ["sync"])

        assert result.exit_code != 0
        assert "not running" in result.output.lower()


class TestLifecycleStatus:
    """Tests for safeyolo status with service validation."""

    def test_status_shows_valid_mappings(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify status shows mapping validation results."""
        from safeyolo.cli import app

        # Create matching services.yaml
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        services_path.write_text("""
services:
  claude-code:
    ip: 172.20.0.3
    project: claude-code
""")

        # Mock docker commands
        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "version"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="Docker 24.0", stderr="")

            if args[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")

            if args[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
                )

            if args[:3] == ["docker", "network", "inspect"]:
                mock_output = json.dumps([{
                    "Name": "safeyolo_internal",
                    "Containers": {
                        "proxy-id": {"Name": "safeyolo", "IPv4Address": "172.20.0.2/16"},
                        "agent-id": {"Name": "claude-code", "IPv4Address": "172.20.0.3/16"},
                    }
                }])
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=mock_output, stderr="")

            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = cli_runner.invoke(app, ["status"])

        # Should show valid mappings
        assert "valid" in result.output.lower() or "mapping" in result.output.lower()

    def test_status_shows_stale_issues(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify status detects stale/mismatched mappings."""
        from safeyolo.cli import app

        # Create stale services.yaml (container no longer running)
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        services_path.write_text("""
services:
  old-agent:
    ip: 172.20.0.99
    project: old-agent
""")

        # Mock docker commands - network has no old-agent
        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "version"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="Docker 24.0", stderr="")

            if args[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")

            if args[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
                )

            if args[:3] == ["docker", "network", "inspect"]:
                mock_output = json.dumps([{
                    "Name": "safeyolo_internal",
                    "Containers": {
                        "proxy-id": {"Name": "safeyolo", "IPv4Address": "172.20.0.2/16"},
                    }
                }])
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=mock_output, stderr="")

            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = cli_runner.invoke(app, ["status"])

        # Should show issues
        assert "stale" in result.output.lower() or "issue" in result.output.lower() or "sync" in result.output.lower()


class TestDockerNetworkConflict:
    """Tests for Docker network conflict handling."""

    def test_start_succeeds_with_no_static_subnet(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify start works when Docker assigns from available pool."""
        from safeyolo.cli import app

        # Track state: initially not running, then running after compose up
        started = {"value": False}

        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "version"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="Docker 24.0", stderr="")

            if args[:2] == ["docker", "ps"]:
                # Initially not running, then running after compose up
                if started["value"]:
                    return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")
                else:
                    return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            if args[:2] == ["docker", "inspect"]:
                return subprocess.CompletedProcess(
                    args=args, returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
                )

            if args[:3] == ["docker", "network", "inspect"]:
                # Docker picked a different subnet (not 172.31.x.x)
                mock_output = json.dumps([{
                    "Name": "safeyolo_internal",
                    "Containers": {
                        "proxy-id": {"Name": "safeyolo", "IPv4Address": "172.25.0.2/16"},
                        "agent-id": {"Name": "claude-code", "IPv4Address": "172.25.0.3/16"},
                    }
                }])
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=mock_output, stderr="")

            if "compose" in args and "up" in args:
                started["value"] = True
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            if "compose" in args:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        cli_runner.invoke(app, ["start", "--no-wait"])

        # Should succeed with the Docker-assigned IPs
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        assert services_path.exists()

        content = yaml.safe_load(services_path.read_text())
        assert content["services"]["claude-code"]["ip"] == "172.25.0.3"


class TestAgentLifecycle:
    """Tests for agent run/remove with service discovery."""

    def test_agent_remove_updates_services(self, tmp_safeyolo_env, cli_runner, monkeypatch):
        """Verify agent remove triggers service regeneration."""
        from safeyolo.cli import app

        # Create agent directory
        agent_dir = tmp_safeyolo_env / "agents" / "test-agent"
        agent_dir.mkdir(parents=True)
        (agent_dir / "docker-compose.yml").write_text("services:\n  test-agent:\n    image: test")

        # Create services.yaml with the agent
        services_path = tmp_safeyolo_env / "data" / "services.yaml"
        services_path.write_text("""
services:
  test-agent:
    ip: 172.20.0.5
    project: test-agent
""")

        # Mock docker commands
        def mock_run(args, **kwargs):
            if args[:2] == ["docker", "ps"]:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")

            if args[:3] == ["docker", "network", "inspect"]:
                # Agent container no longer on network
                mock_output = json.dumps([{
                    "Name": "safeyolo_internal",
                    "Containers": {
                        "proxy-id": {"Name": "safeyolo", "IPv4Address": "172.20.0.2/16"},
                    }
                }])
                return subprocess.CompletedProcess(args=args, returncode=0, stdout=mock_output, stderr="")

            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)

        result = cli_runner.invoke(app, ["agent", "remove", "test-agent"])

        assert "Removed" in result.output

        # Agent directory should be deleted
        assert not agent_dir.exists()

        # services.yaml should be regenerated (agent gone)
        content = yaml.safe_load(services_path.read_text())
        assert "test-agent" not in content.get("services", {})
