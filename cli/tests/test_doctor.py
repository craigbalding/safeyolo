"""Tests for safeyolo doctor command."""

import json
import subprocess
from unittest.mock import MagicMock

import yaml

from safeyolo.commands.doctor import (
    DiagResult,
    _build_bundle,
    _check_baseline,
    _check_ca_cert,
    _check_config_dir,
    _check_crash_logs,
    _check_docker,
    _check_log_health,
    _run_checks,
)


class TestCheckConfigDir:
    def test_config_dir_exists(self, tmp_config_dir):
        result = _check_config_dir()
        assert result.status == "pass"
        assert "Found" in result.message

    def test_config_dir_missing(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = _check_config_dir()
        assert result.status == "fail"
        assert "safeyolo init" in result.remediation


class TestCheckDocker:
    def test_docker_available(self, monkeypatch):
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="27.5.0", stderr="")
        )
        monkeypatch.setattr("subprocess.run", mock_run)
        monkeypatch.setattr("safeyolo.commands.doctor.check_docker", lambda: True)
        result = _check_docker()
        assert result.status == "pass"
        assert "27.5.0" in result.message

    def test_docker_unavailable(self, monkeypatch):
        monkeypatch.setattr("safeyolo.commands.doctor.check_docker", lambda: False)
        result = _check_docker()
        assert result.status == "fail"


class TestCheckBaseline:
    def test_valid_baseline(self, tmp_config_dir):
        baseline = tmp_config_dir / "policy.yaml"
        baseline.write_text(yaml.dump({
            "metadata": {"version": "1.0"},
            "permissions": [
                {"action": "network:request", "resource": "*", "effect": "allow"},
            ],
        }))
        result = _check_baseline()
        assert result.status == "pass"
        assert "1 permissions" in result.message

    def test_missing_baseline(self, tmp_config_dir):
        result = _check_baseline()
        assert result.status == "fail"
        assert "not found" in result.message

    def test_invalid_yaml(self, tmp_config_dir):
        baseline = tmp_config_dir / "policy.yaml"
        baseline.write_text("invalid: yaml: [broken")
        result = _check_baseline()
        assert result.status == "fail"

    def test_missing_permissions(self, tmp_config_dir):
        baseline = tmp_config_dir / "policy.yaml"
        baseline.write_text(yaml.dump({"metadata": {"version": "1.0"}}))
        result = _check_baseline()
        assert result.status == "warn"


class TestCheckCrashLogs:
    def test_no_crashes(self, tmp_config_dir):
        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        log_file = logs_dir / "mitmproxy.log"
        log_file.write_text("2024-01-01 INFO normal log line\n" * 10)
        result = _check_crash_logs()
        assert result.status == "pass"

    def test_traceback_found(self, tmp_config_dir):
        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        log_file = logs_dir / "mitmproxy.log"
        log_file.write_text(
            "2024-01-01 INFO normal\n"
            "Traceback (most recent call last):\n"
            "  File \"foo.py\", line 1\n"
            "SyntaxError: invalid syntax\n"
        )
        result = _check_crash_logs()
        assert result.status == "warn"
        assert "traceback" in result.message.lower()

    def test_no_log_file(self, tmp_config_dir):
        result = _check_crash_logs()
        assert result.status == "pass"


class TestCheckLogHealth:
    def test_healthy_logs(self, tmp_config_dir):
        from safeyolo.config import get_logs_dir

        logs_dir = get_logs_dir()
        jsonl = logs_dir / "safeyolo.jsonl"
        jsonl.write_text('{"event": "test"}\n' * 10)
        result = _check_log_health()
        assert result.status == "pass"

    def test_no_logs_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "nonexistent"))
        result = _check_log_health()
        assert result.status == "pass"


class TestCheckCaCert:
    def test_no_cert(self, tmp_config_dir):
        result = _check_ca_cert()
        assert result.status == "warn"

    def test_invalid_cert(self, tmp_config_dir):
        cert_path = tmp_config_dir / "certs" / "mitmproxy-ca-cert.pem"
        cert_path.write_text("not a valid cert")
        result = _check_ca_cert()
        assert result.status == "fail"


class TestRunChecks:
    def test_cascade_skips(self, tmp_config_dir, monkeypatch):
        """When Docker is unavailable, downstream checks are skipped."""
        monkeypatch.setattr("safeyolo.commands.doctor.check_docker", lambda: False)
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        )
        monkeypatch.setattr("subprocess.run", mock_run)
        results = _run_checks()
        names = {r.name: r.status for r in results}
        assert names["Docker available"] == "fail"
        assert names["Docker network"] == "skip"

    def test_container_down_skips_proxy(self, tmp_config_dir, monkeypatch):
        """When container is down, mitmproxy/admin/proxy checks are skipped."""
        monkeypatch.setattr("safeyolo.commands.doctor.check_docker", lambda: True)
        mock_run = MagicMock()

        def side_effect(args, **kwargs):
            if "version" in args:
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="27.0", stderr="")
            if "inspect" in args and "network" not in str(args):
                return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="not found")
            if "network" in str(args):
                return subprocess.CompletedProcess(args=args, returncode=0, stdout="{}", stderr="")
            return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("subprocess.run", mock_run)
        mock_run.side_effect = side_effect
        results = _run_checks()
        names = {r.name: r.status for r in results}
        assert names["Container running"] == "fail"
        assert names["mitmproxy process"] == "skip"
        assert names["Admin API"] == "skip"
        assert names["Proxy port"] == "skip"


class TestBuildBundle:
    def test_bundle_structure(self, monkeypatch):
        monkeypatch.setattr("subprocess.run", MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=0, stdout="27.0", stderr="")
        ))
        results = [
            DiagResult(name="test1", status="pass", message="ok"),
            DiagResult(name="test2", status="fail", message="bad", detail="traceback here"),
        ]
        bundle = _build_bundle(results)
        assert "timestamp" in bundle
        assert len(bundle["checks"]) == 2
        assert bundle["summary"]["pass"] == 1
        assert bundle["summary"]["fail"] == 1
        assert "docker_version" in bundle["system"]


class TestDoctorCLI:
    def test_doctor_runs(self, cli_runner, tmp_config_dir, monkeypatch):
        """Smoke test that doctor command runs without crashing."""
        monkeypatch.setattr("safeyolo.commands.doctor.check_docker", lambda: False)
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        from safeyolo.cli import app

        result = cli_runner.invoke(app, ["doctor"])
        assert "SafeYolo Doctor" in result.output
        assert "PASS" in result.output or "FAIL" in result.output

    def test_doctor_json(self, cli_runner, tmp_config_dir, monkeypatch):
        """Test --json flag writes bundle file."""
        monkeypatch.setattr("safeyolo.commands.doctor.check_docker", lambda: False)
        mock_run = MagicMock(
            return_value=subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
        )
        monkeypatch.setattr("subprocess.run", mock_run)

        from safeyolo.cli import app

        result = cli_runner.invoke(app, ["doctor", "--json"])
        assert "Bundle written to" in result.output

        # Verify the bundle file was created
        data_dir = tmp_config_dir / "data"
        json_files = list(data_dir.glob("doctor_*.json"))
        assert len(json_files) == 1
        bundle = json.loads(json_files[0].read_text())
        assert "checks" in bundle
        assert "summary" in bundle
