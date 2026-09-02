"""Shared fixtures for SafeYolo CLI tests."""

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from unittest.mock import create_autospec

import httpx
import pytest
from typer.testing import CliRunner

# Production proxy startup puts the repository root on PYTHONPATH so the
# package-external ``pdp`` module is available to directly registered addons.
# Mirror that environment for TrafficMaster composition tests.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PROJECT_ROOT))


# ---------- NATS runtime fixtures ----------
# Shared between test_coord_nats_runtime.py and test_coord_nats_client.py
# so the binary download happens once per session across both files.


@pytest.fixture
def isolated_coord(tmp_path, monkeypatch):
    """Give each test its own coord state, NATS identity, and ports."""
    monkeypatch.setenv("SAFEYOLO_COORD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SAFEYOLO_NATS_TEST_INSTANCE", secrets.token_hex(8))
    return tmp_path


@pytest.fixture(scope="session")
def _binary_cache(tmp_path_factory):
    """Download the nats-server binary once per session."""
    from safeyolo.coord import nats_runtime as nr
    cache_dir = tmp_path_factory.mktemp("nats-binary-cache")
    orig_env = os.environ.get("SAFEYOLO_COORD_DATA_DIR")
    os.environ["SAFEYOLO_COORD_DATA_DIR"] = str(cache_dir)
    try:
        try:
            binary = nr.ensure_binary()
        except Exception as e:
            pytest.skip(f"nats-server binary unavailable: {e!s}")
        return binary
    finally:
        if orig_env is None:
            os.environ.pop("SAFEYOLO_COORD_DATA_DIR", None)
        else:
            os.environ["SAFEYOLO_COORD_DATA_DIR"] = orig_env


@pytest.fixture
def nats_env(isolated_coord, _binary_cache):
    """Test-owned state with a real NATS binary and dynamic endpoints.

    Any server started by the test is ownership-verified and stopped during
    teardown. The fixture never probes or signals the production ports.
    """
    from safeyolo.coord import nats_runtime as nr
    dest = nr.nats_binary_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        os.symlink(_binary_cache, dest)
    yield isolated_coord
    try:
        nr.stop_server()
    finally:
        nr.nats_test_endpoints_path().unlink(missing_ok=True)


class _HTTPResponseBoundary:
    """Small concrete response surface used by the AdminAPI transport mock."""

    def __init__(self) -> None:
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self.text = '{"status": "healthy"}'

    def json(self):
        return {"status": "healthy"}


@pytest.fixture
def cli_runner():
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    """Create temp safeyolo config directory with proper isolation.

    Uses environment variable overrides (SAFEYOLO_CONFIG_DIR, SAFEYOLO_LOGS_DIR)
    which are checked by the config accessor functions at call time.
    """
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    (config_dir / "certs").mkdir()
    (config_dir / "policies").mkdir()
    (config_dir / "data").mkdir()

    # Logs go to XDG state directory (separate from config)
    logs_dir = tmp_path / ".local" / "state" / "safeyolo"
    logs_dir.mkdir(parents=True)

    # Write minimal config
    (config_dir / "config.yaml").write_text(
        "version: 1\nproxy:\n  port: 8080\n  admin_port: 9090\n  container_name: safeyolo-test\n"
    )

    # Write minimal policy.toml (agents_store reads/writes [agents] here)
    (config_dir / "policy.toml").write_text(
        'version = "2.0"\n\n[hosts]\n"*" = { rate = 600 }\n'
    )

    # Set environment variables - accessor functions check these at call time
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs_dir))

    return config_dir


@pytest.fixture
def mock_subprocess(monkeypatch):
    """Mock subprocess.run for external commands."""
    mock_run = create_autospec(subprocess.run, spec_set=True)
    mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    monkeypatch.setattr("subprocess.run", mock_run)
    return mock_run


@pytest.fixture
def mock_httpx(monkeypatch):
    """Mock httpx.Client for API calls."""
    mock_client = create_autospec(httpx.Client, instance=True, spec_set=True)
    mock_response = create_autospec(_HTTPResponseBoundary(), spec_set=True)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {"status": "healthy"}
    mock_response.text = '{"status": "healthy"}'

    mock_client.__enter__.return_value = mock_client
    mock_client.__exit__.return_value = False
    mock_client.request.return_value = mock_response

    mock_client_class = create_autospec(httpx.Client, spec_set=True)
    mock_client_class.return_value = mock_client
    monkeypatch.setattr("httpx.Client", mock_client_class)

    return {
        "client_class": mock_client_class,
        "client": mock_client,
        "response": mock_response,
    }




@pytest.fixture
def sample_log_events():
    """Sample JSONL log events matching AuditEvent contract."""
    return [
        {
            "ts": "2024-01-01T12:00:00Z",
            "event": "traffic.request",
            "kind": "traffic",
            "severity": "low",
            "summary": "POST api.openai.com/v1/chat",
            "host": "api.openai.com",
            "agent": "claude-code",
            "details": {"method": "POST", "path": "/v1/chat", "size": 1234, "client": "172.18.0.3"},
        },
        {
            "ts": "2024-01-01T12:00:01Z",
            "event": "traffic.response",
            "kind": "traffic",
            "severity": "low",
            "summary": "200 api.openai.com/v1/chat",
            "host": "api.openai.com",
            "agent": "claude-code",
            "decision": "allow",
            "details": {"path": "/v1/chat", "status": 200, "size": 5678, "ms": 150, "client": "172.18.0.3"},
        },
        {
            "ts": "2024-01-01T12:00:02Z",
            "event": "security.credential",
            "kind": "security",
            "severity": "high",
            "summary": "openai cred sent to httpbin.org",
            "host": "httpbin.org",
            "agent": "claude-code",
            "decision": "block",
            "details": {"credential_type": "openai", "reason": "destination_mismatch", "client": "172.18.0.3"},
        },
        {
            "ts": "2024-01-01T12:00:03Z",
            "event": "security.ratelimit",
            "kind": "security",
            "severity": "medium",
            "summary": "rate limit warning for api.openai.com",
            "host": "api.openai.com",
            "agent": "other-agent",
            "decision": "warn",
            "details": {"wait_ms": 500, "client": "172.18.0.4"},
        },
    ]


@pytest.fixture
def write_log_file(tmp_config_dir, sample_log_events):
    """Write sample log events to JSONL file."""
    from safeyolo.config import get_logs_dir

    logs_dir = get_logs_dir()
    log_file = logs_dir / "safeyolo.jsonl"
    with open(log_file, "w") as f:
        for event in sample_log_events:
            f.write(json.dumps(event) + "\n")
    return log_file
