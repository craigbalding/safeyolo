"""Tests for Docker operations module."""

import subprocess

import pytest

from safeyolo.docker import (
    DockerError,
    check_docker,
    generate_compose_file,
    get_container_name,
    get_container_status,
    is_running,
    start,
    stop,
    wait_for_healthy,
    write_compose_file,
)


class TestCheckDocker:
    """Tests for check_docker()."""

    def test_returns_true_if_available(self, mock_subprocess):
        """Returns True if docker command succeeds."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=["docker", "version"], returncode=0, stdout="Docker 24.0", stderr=""
        )
        assert check_docker() is True

    def test_returns_false_if_unavailable(self, mock_subprocess):
        """Returns False if docker command fails."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=["docker", "version"], returncode=1, stdout="", stderr="not found"
        )
        assert check_docker() is False

    def test_returns_false_if_not_installed(self, monkeypatch):
        """Returns False if docker not installed."""

        def raise_not_found(*args, **kwargs):
            raise FileNotFoundError("docker not found")

        monkeypatch.setattr("subprocess.run", raise_not_found)
        assert check_docker() is False


class TestGetContainerName:
    """Tests for get_container_name()."""

    def test_from_config(self, tmp_config_dir):
        """Gets container name from config."""
        name = get_container_name()
        assert name == "safeyolo-test"

    def test_default_value(self, monkeypatch):
        """Returns 'safeyolo' when config has no container_name."""
        # Config without container_name - tests the .get() fallback
        minimal_config = {"proxy": {"port": 8080}}
        monkeypatch.setattr("safeyolo.docker.load_config", lambda: minimal_config)
        name = get_container_name()
        assert name == "safeyolo"


class TestIsRunning:
    """Tests for is_running()."""

    def test_running_container(self, tmp_config_dir, mock_subprocess):
        """Returns True if container running."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="abc123\n", stderr=""
        )
        assert is_running() is True

    def test_not_running(self, tmp_config_dir, mock_subprocess):
        """Returns False if container not running."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        assert is_running() is False


class TestGetContainerStatus:
    """Tests for get_container_status()."""

    def test_returns_status_dict(self, tmp_config_dir, mock_subprocess):
        """Returns status dictionary."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
        )
        status = get_container_status()
        assert status["status"] == "running"
        assert status["health"] == "healthy"
        assert "2024-01-01" in status["started_at"]

    def test_returns_none_if_not_found(self, tmp_config_dir, mock_subprocess):
        """Returns None if container doesn't exist."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="No such container"
        )
        status = get_container_status()
        assert status is None

    def test_handles_no_health_check(self, tmp_config_dir, mock_subprocess):
        """Handles containers without health checks."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="running||2024-01-01T00:00:00Z", stderr=""
        )
        status = get_container_status()
        assert status["health"] == "none"


class TestGenerateComposeFile:
    """Tests for generate_compose_file()."""

    def test_generates_valid_yaml(self, tmp_config_dir):
        """Generates valid docker-compose YAML."""
        content = generate_compose_file()
        assert "services:" in content
        assert "safeyolo:" in content
        assert "8080:8080" in content
        assert "9090:9090" in content

    def test_includes_volumes(self, tmp_config_dir):
        """Includes volume mounts."""
        content = generate_compose_file()
        assert "/app/logs" in content
        assert "/certs" in content
        assert "/app/data" in content

    def test_includes_rules_if_exists(self, tmp_config_dir):
        """Includes rules.json mount if file exists."""
        (tmp_config_dir / "rules.json").write_text("{}")
        content = generate_compose_file()
        assert "credential_rules.json" in content

    def test_includes_environment(self, tmp_config_dir):
        """Includes environment variables."""
        content = generate_compose_file()
        assert "SAFEYOLO_BLOCK=true" in content

    def test_includes_healthcheck(self, tmp_config_dir):
        """Includes health check configuration."""
        content = generate_compose_file()
        assert "healthcheck:" in content
        assert "/health" in content


class TestWriteComposeFile:
    """Tests for write_compose_file()."""

    def test_writes_to_config_dir(self, tmp_config_dir):
        """Writes docker-compose.yml to config directory."""
        path = write_compose_file()
        assert path == tmp_config_dir / "docker-compose.yml"
        assert path.exists()
        assert "services:" in path.read_text()


class TestStart:
    """Tests for start()."""

    def test_starts_container(self, tmp_config_dir, mock_docker_available):
        """Starts container with docker compose."""
        start()

        # Find compose up call
        calls = mock_docker_available.call_args_list
        compose_calls = [c for c in calls if "compose" in str(c)]
        assert len(compose_calls) > 0

    def test_pulls_if_requested(self, tmp_config_dir, mock_docker_available):
        """Pulls image if pull=True."""
        start(pull=True)

        calls = mock_docker_available.call_args_list
        pull_calls = [c for c in calls if "pull" in str(c)]
        assert len(pull_calls) > 0

    def test_raises_if_docker_unavailable(self, tmp_config_dir, mock_subprocess):
        """Raises DockerError if Docker not available."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=""
        )
        with pytest.raises(DockerError, match="Docker is not available"):
            start()


class TestStop:
    """Tests for stop()."""

    def test_stops_with_compose(self, tmp_config_dir, mock_subprocess):
        """Stops container with docker compose down."""
        # First write compose file
        write_compose_file()

        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        stop()

        calls = mock_subprocess.call_args_list
        down_calls = [c for c in calls if "down" in str(c)]
        assert len(down_calls) > 0

    def test_stops_directly_without_compose(self, tmp_config_dir, mock_subprocess):
        """Falls back to docker stop if no compose file."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        stop()

        calls = mock_subprocess.call_args_list
        stop_calls = [c for c in calls if "stop" in str(c)]
        assert len(stop_calls) > 0


class TestWaitForHealthy:
    """Tests for wait_for_healthy()."""

    def test_returns_true_when_healthy(self, tmp_config_dir, mock_subprocess):
        """Returns True when container becomes healthy."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
        )
        result = wait_for_healthy(timeout=5)
        assert result is True

    def test_returns_false_on_timeout(self, tmp_config_dir, mock_subprocess):
        """Returns False if timeout reached."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="running|starting|2024-01-01T00:00:00Z", stderr=""
        )
        result = wait_for_healthy(timeout=1)
        assert result is False

    def test_returns_false_if_stopped(self, tmp_config_dir, mock_subprocess):
        """Returns False if container stops."""
        mock_subprocess.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="exited||2024-01-01T00:00:00Z", stderr=""
        )
        result = wait_for_healthy(timeout=5)
        assert result is False


class TestDockerError:
    """Tests for DockerError exception."""

    def test_includes_message(self):
        """Stores error message."""
        err = DockerError("Command failed")
        assert "Command failed" in str(err)
