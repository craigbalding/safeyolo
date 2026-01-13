"""Tests for Docker operations module."""

import subprocess

import pytest
import yaml

from safeyolo.docker import (
    DockerError,
    check_docker,
    generate_compose,
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


class TestGenerateCompose:
    """Tests for generate_compose()."""

    def test_generates_valid_yaml_sandbox(self, tmp_config_dir):
        """Generates valid docker-compose YAML for sandbox mode."""
        content = generate_compose(sandbox=True)
        assert "services:" in content
        assert "safeyolo:" in content
        # Ports should be localhost-bound
        assert "127.0.0.1:" in content
        assert "8080" in content
        assert "9090" in content

    def test_generates_valid_yaml_try_mode(self, tmp_config_dir):
        """Generates valid docker-compose YAML for try mode."""
        content = generate_compose(sandbox=False)
        assert "services:" in content
        assert "safeyolo:" in content
        # Ports should be localhost-bound in try mode too
        assert "127.0.0.1:" in content

    def test_includes_volumes(self, tmp_config_dir):
        """Includes volume mounts."""
        content = generate_compose(sandbox=True)
        assert "/app/logs" in content
        assert "/certs-private" in content
        assert "/app/data" in content

    def test_includes_rules_if_exists(self, tmp_config_dir):
        """Includes rules.json mount if file exists."""
        (tmp_config_dir / "rules.json").write_text("{}")
        content = generate_compose(sandbox=True)
        assert "credential_rules.json" in content

    def test_includes_environment(self, tmp_config_dir):
        """Includes environment variables."""
        content = generate_compose(sandbox=True)
        assert "SAFEYOLO_BLOCK=true" in content

    def test_includes_healthcheck(self, tmp_config_dir):
        """Includes health check configuration."""
        content = generate_compose(sandbox=True)
        assert "healthcheck:" in content
        assert "/health" in content

    def test_sandbox_includes_internal_network(self, tmp_config_dir):
        """Sandbox mode includes internal network definition."""
        content = generate_compose(sandbox=True)
        assert "internal: true" in content
        # Network is named "internal" in compose; Docker Compose prefixes with project name at runtime
        assert "\n  internal:\n" in content  # Network definition under networks:

    def test_try_mode_no_internal_network(self, tmp_config_dir):
        """Try mode does not include internal network."""
        content = generate_compose(sandbox=False)
        assert "internal: true" not in content

    def test_includes_user_directive(self, tmp_config_dir):
        """Both modes include non-root user directive."""
        for sandbox in (True, False):
            content = generate_compose(sandbox=sandbox)
            assert "user:" in content

    def test_sandbox_includes_certs_init(self, tmp_config_dir):
        """Sandbox mode includes certs-init service."""
        content = generate_compose(sandbox=True)
        assert "certs-init:" in content

    def test_try_mode_no_certs_init(self, tmp_config_dir):
        """Try mode does not include certs-init service."""
        content = generate_compose(sandbox=False)
        assert "certs-init:" not in content


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


class TestComposeSecurityProperties:
    """Verify security properties in generated compose YAML.

    These tests parse the generated YAML and verify security-critical properties:
    - Localhost-only port bindings
    - Non-root user directive
    - Internal network isolation (sandbox mode)
    - Private cert volume isolation
    """

    def test_all_ports_localhost_bound_sandbox(self, tmp_config_dir):
        """Sandbox mode: all ports must be 127.0.0.1 bound."""
        content = generate_compose(sandbox=True)
        parsed = yaml.safe_load(content)

        for svc_name, svc in parsed.get("services", {}).items():
            for port in svc.get("ports", []):
                port_str = str(port)
                assert port_str.startswith("127.0.0.1:"), \
                    f"Service {svc_name} port not localhost-bound: {port}"

    def test_all_ports_localhost_bound_try(self, tmp_config_dir):
        """Try mode: all ports must be 127.0.0.1 bound."""
        content = generate_compose(sandbox=False)
        parsed = yaml.safe_load(content)

        for svc_name, svc in parsed.get("services", {}).items():
            for port in svc.get("ports", []):
                port_str = str(port)
                assert port_str.startswith("127.0.0.1:"), \
                    f"Service {svc_name} port not localhost-bound: {port}"

    def test_sandbox_has_internal_network(self, tmp_config_dir):
        """Sandbox mode must create internal network with no gateway."""
        content = generate_compose(sandbox=True)
        parsed = yaml.safe_load(content)

        networks = parsed.get("networks", {})
        # Network is named "internal" in compose; Docker Compose prefixes with project name at runtime
        internal_net = networks.get("internal")

        assert internal_net is not None, "Sandbox mode missing internal network"
        assert internal_net.get("internal") is True, \
            "Internal network not marked as internal (no gateway isolation)"

    def test_try_mode_no_internal_network(self, tmp_config_dir):
        """Try mode should not create internal network."""
        content = generate_compose(sandbox=False)
        parsed = yaml.safe_load(content)

        networks = parsed.get("networks", {})
        assert "safeyolo_internal" not in networks, \
            "Try mode should not have internal network"

    def test_safeyolo_runs_nonroot(self, tmp_config_dir):
        """Safeyolo service must have non-root user directive."""
        for sandbox in (True, False):
            content = generate_compose(sandbox=sandbox)
            parsed = yaml.safe_load(content)

            user = parsed["services"]["safeyolo"].get("user")
            assert user is not None, f"No user directive (sandbox={sandbox})"

            uid = str(user).split(":")[0]
            assert uid not in ("0", "root"), \
                f"Runs as root (sandbox={sandbox}): {user}"

    def test_private_volume_only_safeyolo(self, tmp_config_dir):
        """Private cert volume should only be mounted by safeyolo/certs-init."""
        for sandbox in (True, False):
            content = generate_compose(sandbox=sandbox)
            parsed = yaml.safe_load(content)

            allowed_services = {"safeyolo", "certs-init"}

            for svc_name, svc in parsed.get("services", {}).items():
                if svc_name in allowed_services:
                    continue

                volumes = svc.get("volumes", [])
                for vol in volumes:
                    assert "certs-private" not in str(vol), \
                        f"Service {svc_name} has access to private certs!"

    def test_public_ca_volume_exists_sandbox(self, tmp_config_dir):
        """Sandbox mode should define public CA volume."""
        content = generate_compose(sandbox=True)
        parsed = yaml.safe_load(content)

        volumes = parsed.get("volumes", {})
        has_ca_volume = "safeyolo-ca" in volumes or any(
            "ca" in str(v).lower() for v in volumes
        )
        assert has_ca_volume, "Sandbox mode missing public CA volume"

    def test_sandbox_safeyolo_on_both_networks(self, tmp_config_dir):
        """Sandbox mode: safeyolo must be on internal and default networks."""
        content = generate_compose(sandbox=True)
        parsed = yaml.safe_load(content)

        safeyolo_networks = parsed["services"]["safeyolo"].get("networks", {})
        # Network is named "internal" in compose; Docker Compose prefixes with project name at runtime
        assert "internal" in safeyolo_networks, \
            "Safeyolo not on internal network"
        assert "default" in safeyolo_networks, \
            "Safeyolo not on default network (no internet access)"

    def test_certs_init_runs_as_root(self, tmp_config_dir):
        """Certs-init must run as root to set permissions."""
        content = generate_compose(sandbox=True)
        parsed = yaml.safe_load(content)

        certs_init = parsed["services"].get("certs-init")
        assert certs_init is not None, "Missing certs-init service"

        user = certs_init.get("user")
        assert user == "0:0", f"Certs-init should run as root, got: {user}"
