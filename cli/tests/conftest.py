"""Shared fixtures for SafeYolo CLI tests."""

import json
import subprocess
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner


@pytest.fixture
def cli_runner():
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    """Create temp safeyolo config directory and set as cwd."""
    config_dir = tmp_path / "safeyolo"
    config_dir.mkdir()
    (config_dir / "logs").mkdir()
    (config_dir / "certs").mkdir()
    (config_dir / "policies").mkdir()
    (config_dir / "data").mkdir()

    # Write minimal config
    (config_dir / "config.yaml").write_text(
        "version: 1\n"
        "proxy:\n"
        "  port: 8080\n"
        "  admin_port: 9090\n"
        "  container_name: safeyolo-test\n"
    )

    # Change to parent so find_config_dir() finds ./safeyolo/
    monkeypatch.chdir(tmp_path)
    return config_dir


@pytest.fixture
def mock_subprocess(monkeypatch):
    """Mock subprocess.run for docker commands."""
    mock_run = MagicMock()
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )
    monkeypatch.setattr("subprocess.run", mock_run)
    return mock_run


@pytest.fixture
def mock_httpx(monkeypatch):
    """Mock httpx.Client for API calls."""
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {"status": "healthy"}
    mock_response.text = '{"status": "healthy"}'

    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.request = MagicMock(return_value=mock_response)

    mock_client_class = MagicMock(return_value=mock_client)
    monkeypatch.setattr("httpx.Client", mock_client_class)

    return {
        "client_class": mock_client_class,
        "client": mock_client,
        "response": mock_response,
    }


@pytest.fixture
def mock_docker_available(mock_subprocess):
    """Mock docker as available but container not running."""

    def run_side_effect(args, **kwargs):
        if args[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Docker 24.0", stderr="")
        if args[:2] == ["docker", "ps"]:
            # Container not running - empty output
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        if "compose" in args:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    mock_subprocess.side_effect = run_side_effect
    return mock_subprocess


@pytest.fixture
def mock_docker_running(mock_subprocess):
    """Mock docker container as running."""

    def run_side_effect(args, **kwargs):
        if args[:2] == ["docker", "version"]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="Docker 24.0", stderr="")
        if args[:2] == ["docker", "ps"]:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="abc123\n", stderr="")
        if args[:2] == ["docker", "inspect"]:
            return subprocess.CompletedProcess(
                args=args, returncode=0, stdout="running|healthy|2024-01-01T00:00:00Z", stderr=""
            )
        if "compose" in args:
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    mock_subprocess.side_effect = run_side_effect
    return mock_subprocess


@pytest.fixture
def sample_log_events():
    """Sample JSONL log events for testing."""
    return [
        {"ts": "2024-01-01T12:00:00Z", "event": "traffic.request", "host": "api.openai.com", "method": "POST", "path": "/v1/chat"},
        {"ts": "2024-01-01T12:00:01Z", "event": "traffic.response", "status": 200, "latency_ms": 150},
        {"ts": "2024-01-01T12:00:02Z", "event": "security.credential", "decision": "block", "host": "httpbin.org", "rule": "openai"},
        {"ts": "2024-01-01T12:00:03Z", "event": "security.ratelimit", "decision": "warn", "domain": "api.openai.com", "wait_ms": 500},
    ]


@pytest.fixture
def write_log_file(tmp_config_dir, sample_log_events):
    """Write sample log events to JSONL file."""
    log_file = tmp_config_dir / "logs" / "safeyolo.jsonl"
    with open(log_file, "w") as f:
        for event in sample_log_events:
            f.write(json.dumps(event) + "\n")
    return log_file
