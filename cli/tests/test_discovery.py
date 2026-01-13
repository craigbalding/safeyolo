"""Tests for discovery.py - Dynamic IP discovery from Docker network state."""

import json
import subprocess
from unittest.mock import MagicMock

import pytest
import yaml


class TestQueryNetworkContainers:
    """Tests for query_network_containers()."""

    def test_parses_docker_network_inspect(self, monkeypatch):
        """Parses docker network inspect JSON output."""
        from safeyolo.discovery import query_network_containers

        mock_output = json.dumps([{
            "Name": "safeyolo_internal",
            "Containers": {
                "abc123": {"Name": "safeyolo", "IPv4Address": "172.20.0.2/16"},
                "def456": {"Name": "claude-code", "IPv4Address": "172.20.0.3/16"},
                "ghi789": {"Name": "openai-codex", "IPv4Address": "172.20.0.4/16"},
            }
        }])

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout=mock_output, stderr=""
        ))
        monkeypatch.setattr("subprocess.run", mock_run)

        result = query_network_containers("safeyolo_internal")

        assert result == {
            "safeyolo": "172.20.0.2",
            "claude-code": "172.20.0.3",
            "openai-codex": "172.20.0.4",
        }

    def test_returns_empty_dict_for_nonexistent_network(self, monkeypatch):
        """Returns empty dict when network doesn't exist."""
        from safeyolo.discovery import query_network_containers

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="No such network: missing-network"
        ))
        mock_run.side_effect = subprocess.CalledProcessError(
            1, [], stderr="No such network: missing-network"
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        result = query_network_containers("missing-network")
        assert result == {}

    def test_returns_empty_dict_for_empty_network(self, monkeypatch):
        """Returns empty dict when network has no containers."""
        from safeyolo.discovery import query_network_containers

        mock_output = json.dumps([{"Name": "safeyolo_internal", "Containers": {}}])
        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout=mock_output, stderr=""
        ))
        monkeypatch.setattr("subprocess.run", mock_run)

        result = query_network_containers()
        assert result == {}

    def test_raises_discovery_error_on_docker_failure(self, monkeypatch):
        """Raises DiscoveryError when docker command fails."""
        from safeyolo.discovery import DiscoveryError, query_network_containers

        mock_run = MagicMock()
        mock_run.side_effect = subprocess.CalledProcessError(
            1, [], stderr="Some docker error"
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        with pytest.raises(DiscoveryError, match="Failed to inspect network"):
            query_network_containers()

    def test_raises_discovery_error_when_docker_not_found(self, monkeypatch):
        """Raises DiscoveryError when docker is not installed."""
        from safeyolo.discovery import DiscoveryError, query_network_containers

        mock_run = MagicMock()
        mock_run.side_effect = FileNotFoundError("docker not found")
        monkeypatch.setattr("subprocess.run", mock_run)

        with pytest.raises(DiscoveryError, match="Docker not found"):
            query_network_containers()

    def test_handles_malformed_json(self, monkeypatch):
        """Raises DiscoveryError on malformed JSON."""
        from safeyolo.discovery import DiscoveryError, query_network_containers

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout="not valid json", stderr=""
        ))
        monkeypatch.setattr("subprocess.run", mock_run)

        with pytest.raises(DiscoveryError, match="Failed to parse"):
            query_network_containers()

    def test_skips_containers_without_ipv4(self, monkeypatch):
        """Skips containers that don't have IPv4 addresses."""
        from safeyolo.discovery import query_network_containers

        mock_output = json.dumps([{
            "Name": "safeyolo_internal",
            "Containers": {
                "abc123": {"Name": "has-ip", "IPv4Address": "172.20.0.2/16"},
                "def456": {"Name": "no-ip", "IPv4Address": ""},
                "ghi789": {"Name": "missing-field"},
            }
        }])

        mock_run = MagicMock(return_value=subprocess.CompletedProcess(
            args=[], returncode=0, stdout=mock_output, stderr=""
        ))
        monkeypatch.setattr("subprocess.run", mock_run)

        result = query_network_containers()
        assert result == {"has-ip": "172.20.0.2"}


class TestWriteServicesYaml:
    """Tests for write_services_yaml()."""

    def test_writes_valid_yaml(self, tmp_path):
        """Writes valid YAML with services structure."""
        from safeyolo.discovery import write_services_yaml

        output_path = tmp_path / "services.yaml"
        container_ips = {
            "claude-code": "172.20.0.3",
            "openai-codex": "172.20.0.4",
        }

        result = write_services_yaml(container_ips, output_path)

        assert result == output_path
        assert output_path.exists()

        content = yaml.safe_load(output_path.read_text())
        assert "services" in content
        assert content["services"]["claude-code"]["ip"] == "172.20.0.3"
        assert content["services"]["openai-codex"]["ip"] == "172.20.0.4"

    def test_skips_safeyolo_proxy(self, tmp_path):
        """Excludes safeyolo proxy from services mapping."""
        from safeyolo.discovery import write_services_yaml

        output_path = tmp_path / "services.yaml"
        container_ips = {
            "safeyolo": "172.20.0.2",
            "claude-code": "172.20.0.3",
        }

        write_services_yaml(container_ips, output_path)

        content = yaml.safe_load(output_path.read_text())
        assert "safeyolo" not in content["services"]
        assert "claude-code" in content["services"]

    def test_includes_header_comments(self, tmp_path):
        """Includes header comments with timestamp."""
        from safeyolo.discovery import write_services_yaml

        output_path = tmp_path / "services.yaml"
        write_services_yaml({"test": "172.20.0.3"}, output_path)

        content = output_path.read_text()
        assert "Auto-generated by safeyolo CLI" in content
        assert "safeyolo sync" in content
        assert "Last updated:" in content

    def test_creates_parent_directories(self, tmp_path):
        """Creates parent directories if needed."""
        from safeyolo.discovery import write_services_yaml

        output_path = tmp_path / "nested" / "dir" / "services.yaml"
        write_services_yaml({"test": "172.20.0.3"}, output_path)

        assert output_path.exists()

    def test_uses_container_name_as_project(self, tmp_path):
        """Uses container name directly as project name."""
        from safeyolo.discovery import write_services_yaml

        output_path = tmp_path / "services.yaml"
        write_services_yaml({"my-agent": "172.20.0.5"}, output_path)

        content = yaml.safe_load(output_path.read_text())
        assert content["services"]["my-agent"]["project"] == "my-agent"


class TestRegenerateServices:
    """Tests for regenerate_services()."""

    def test_queries_and_writes(self, tmp_path, monkeypatch):
        """Queries Docker and writes services.yaml."""
        from safeyolo.discovery import regenerate_services

        # Mock query_network_containers
        mock_query = MagicMock(return_value={
            "safeyolo": "172.20.0.2",
            "claude-code": "172.20.0.3",
        })
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", mock_query)

        # Mock get_services_path
        services_path = tmp_path / "services.yaml"
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        path, count = regenerate_services()

        assert path == services_path
        assert count == 1  # Excludes safeyolo
        assert services_path.exists()

    def test_returns_zero_count_for_empty_network(self, tmp_path, monkeypatch):
        """Returns zero count when no agent containers."""
        from safeyolo.discovery import regenerate_services

        mock_query = MagicMock(return_value={"safeyolo": "172.20.0.2"})
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", mock_query)

        services_path = tmp_path / "services.yaml"
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        path, count = regenerate_services()
        assert count == 0


class TestClearServices:
    """Tests for clear_services()."""

    def test_marks_file_as_stale(self, tmp_path, monkeypatch):
        """Marks services.yaml as stale instead of deleting."""
        from safeyolo.discovery import clear_services

        services_path = tmp_path / "services.yaml"
        services_path.write_text("services:\n  test:\n    ip: 172.20.0.3\n")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        clear_services()

        content = services_path.read_text()
        assert "stale" in content.lower()
        assert "safeyolo stopped" in content.lower()

        config = yaml.safe_load(content)
        assert config["services"] == {}

    def test_noop_if_file_missing(self, tmp_path, monkeypatch):
        """Does nothing if services.yaml doesn't exist."""
        from safeyolo.discovery import clear_services

        services_path = tmp_path / "services.yaml"
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        # Should not raise
        clear_services()
        assert not services_path.exists()


class TestValidateServices:
    """Tests for validate_services()."""

    def test_returns_empty_for_valid_config(self, tmp_path, monkeypatch):
        """Returns empty list when config matches running containers."""
        from safeyolo.discovery import validate_services

        services_path = tmp_path / "services.yaml"
        services_path.write_text("""
services:
  claude-code:
    ip: 172.20.0.3
    project: claude-code
""")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", lambda: {
            "safeyolo": "172.20.0.2",
            "claude-code": "172.20.0.3",
        })

        issues = validate_services()
        assert issues == []

    def test_detects_stale_entries(self, tmp_path, monkeypatch):
        """Detects entries for containers that aren't running."""
        from safeyolo.discovery import validate_services

        services_path = tmp_path / "services.yaml"
        services_path.write_text("""
services:
  old-agent:
    ip: 172.20.0.5
    project: old-agent
""")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", lambda: {
            "safeyolo": "172.20.0.2",
        })

        issues = validate_services()
        assert any("Stale" in issue for issue in issues)
        assert any("old-agent" in issue for issue in issues)

    def test_detects_ip_mismatch(self, tmp_path, monkeypatch):
        """Detects when IP in config doesn't match running container."""
        from safeyolo.discovery import validate_services

        services_path = tmp_path / "services.yaml"
        services_path.write_text("""
services:
  claude-code:
    ip: 172.20.0.99
    project: claude-code
""")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", lambda: {
            "claude-code": "172.20.0.3",
        })

        issues = validate_services()
        assert any("Mismatch" in issue for issue in issues)

    def test_detects_unmapped_containers(self, tmp_path, monkeypatch):
        """Detects containers running but not in services.yaml."""
        from safeyolo.discovery import validate_services

        services_path = tmp_path / "services.yaml"
        services_path.write_text("services: {}")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", lambda: {
            "safeyolo": "172.20.0.2",
            "new-agent": "172.20.0.5",
        })

        issues = validate_services()
        assert any("Unmapped" in issue for issue in issues)
        assert any("new-agent" in issue for issue in issues)

    def test_detects_stale_marker(self, tmp_path, monkeypatch):
        """Detects when services.yaml is marked as stale."""
        from safeyolo.discovery import validate_services

        services_path = tmp_path / "services.yaml"
        services_path.write_text("# SafeYolo stopped - services.yaml is stale\nservices: {}")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)
        monkeypatch.setattr("safeyolo.discovery.query_network_containers", lambda: {})

        issues = validate_services()
        assert any("stale" in issue.lower() for issue in issues)

    def test_reports_missing_file(self, tmp_path, monkeypatch):
        """Reports when services.yaml doesn't exist."""
        from safeyolo.discovery import validate_services

        services_path = tmp_path / "services.yaml"
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        issues = validate_services()
        assert any("does not exist" in issue for issue in issues)


class TestGetServiceMapping:
    """Tests for get_service_mapping()."""

    def test_returns_ip_to_project_mapping(self, tmp_path, monkeypatch):
        """Returns dict mapping IP to project name."""
        from safeyolo.discovery import get_service_mapping

        services_path = tmp_path / "services.yaml"
        services_path.write_text("""
services:
  claude-code:
    ip: 172.20.0.3
    project: claude-code
  openai-codex:
    ip: 172.20.0.4
    project: openai-codex
""")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        mapping = get_service_mapping()

        assert mapping == {
            "172.20.0.3": "claude-code",
            "172.20.0.4": "openai-codex",
        }

    def test_returns_empty_dict_if_file_missing(self, tmp_path, monkeypatch):
        """Returns empty dict when services.yaml doesn't exist."""
        from safeyolo.discovery import get_service_mapping

        services_path = tmp_path / "services.yaml"
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        mapping = get_service_mapping()
        assert mapping == {}

    def test_handles_malformed_yaml(self, tmp_path, monkeypatch):
        """Returns empty dict on YAML parse error."""
        from safeyolo.discovery import get_service_mapping

        services_path = tmp_path / "services.yaml"
        services_path.write_text("not: valid: yaml: content:")
        monkeypatch.setattr("safeyolo.discovery.get_services_path", lambda: services_path)

        # Should not raise, just return empty
        mapping = get_service_mapping()
        assert mapping == {}
