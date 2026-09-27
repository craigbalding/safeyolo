"""Native lifecycle commands keep process ownership and failure behavior explicit."""

from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest
import yaml
from typer.testing import CliRunner

from safeyolo import rust_proxy
from safeyolo.cli import app
from safeyolo.commands import lifecycle


@pytest.fixture
def command(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("SAFEYOLO_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(tmp_path / "logs"))
    for name in ("SAFEYOLO_TIMING", "SAFEYOLO_PROFILE_PATH", "SAFEYOLO_PROFILE_OPERATION"):
        monkeypatch.delenv(name, raising=False)
    mocks = {}
    for name in (
        "check_running_backend", "is_proxy_running", "prior_python_proxy_running",
        "start_proxy", "stop_proxy",
        "wait_for_healthy", "_start_coord_best_effort", "_stop_coord_best_effort",
        "write_event",
    ):
        mock = create_autospec(getattr(lifecycle, name), spec_set=True)
        monkeypatch.setattr(lifecycle, name, mock)
        mocks[name] = mock
    mocks["check_running_backend"].return_value = False
    mocks["is_proxy_running"].return_value = False
    mocks["prior_python_proxy_running"].return_value = False
    mocks["wait_for_healthy"].return_value = True
    mocks["_start_coord_best_effort"].return_value = "healthy"
    process = rust_proxy.RustProcess(
        pid=4321, start_token="owned", readiness_file="/owned/ready.json",
        admin_port=9191, admin_token_file=None, binary_path="/installed/safeyolo-proxy",
    )
    read_process = create_autospec(rust_proxy.read_process, spec_set=True, return_value=process)
    readiness = create_autospec(
        rust_proxy.readiness, spec_set=True,
        return_value={"ready": True, "admin_port": 9191},
    )
    monkeypatch.setattr(rust_proxy, "read_process", read_process)
    monkeypatch.setattr(rust_proxy, "readiness", readiness)
    config_path = config_dir / "config.yaml"

    def configure(backend="rust"):
        config = {"proxy": {"port": 8123, "admin_port": 9191,
                            "backend": backend, "rust_config": "owned-native.json"}}
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return config_path.read_bytes()

    configure()
    return SimpleNamespace(runner=CliRunner(), mocks=mocks, config_path=config_path,
                           configure=configure, process=process, read_process=read_process,
                           readiness=readiness)


def test_start_uses_installed_native_executable(command):
    before = command.config_path.read_bytes()
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 0, result.output
    command.mocks["check_running_backend"].assert_called_once_with()
    command.mocks["start_proxy"].assert_called_once_with()
    command.mocks["wait_for_healthy"].assert_called_once_with(timeout=30)
    command.mocks["_start_coord_best_effort"].assert_called_once_with()
    assert command.config_path.read_bytes() == before
    assert "/installed/safeyolo-proxy" in result.output
    assert "owned-native.json" in result.output


def test_first_run_bootstrap_selects_native_config(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    lifecycle._bootstrap_config(config_dir)
    config = yaml.safe_load((config_dir / "config.yaml").read_text())
    assert config["proxy"]["backend"] == "rust"
    assert config["proxy"]["rust_config"] == str(config_dir / "data" / "native.json")
    assert (config_dir / "lists" / "package-registries.txt").is_file()


@pytest.mark.parametrize("flag", ["--test", "--dev", "--flow-cache"])
def test_removed_development_flags_cannot_start_proxy(command, flag):
    result = command.runner.invoke(app, ["start", flag])
    assert result.exit_code != 0
    command.mocks["start_proxy"].assert_not_called()


def test_python_selector_requires_explicit_package_rollback(command):
    before = command.configure(backend="python")
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1, result.output
    assert "pinned prior package" in result.output
    command.mocks["check_running_backend"].assert_not_called()
    command.mocks["start_proxy"].assert_not_called()
    assert command.config_path.read_bytes() == before


def test_running_native_process_is_not_relaunched(command):
    command.mocks["check_running_backend"].return_value = True
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 0, result.output
    command.mocks["start_proxy"].assert_not_called()
    command.mocks["_start_coord_best_effort"].assert_called_once_with()


def test_native_launch_failure_has_no_fallback(command):
    command.mocks["start_proxy"].side_effect = RuntimeError("native executable is unavailable")
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1, result.output
    assert "native executable is unavailable" in result.output
    command.mocks["wait_for_healthy"].assert_not_called()
    command.mocks["_start_coord_best_effort"].assert_not_called()
    assert command.mocks["write_event"].call_args.kwargs["details"]["phase"] == "launch"


def test_failed_health_stops_native_process(command):
    command.mocks["wait_for_healthy"].return_value = False
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1, result.output
    command.mocks["stop_proxy"].assert_called_once_with()
    command.mocks["_start_coord_best_effort"].assert_not_called()
    assert "native launch diagnostics" in result.output


def test_status_identifies_owned_native_executable(command, monkeypatch):
    command.mocks["is_proxy_running"].return_value = True
    monkeypatch.setattr(lifecycle, "coord_nats", SimpleNamespace(status=lambda: {"state": "not-running"}))
    result = command.runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    assert "Rust" in result.output and "/installed/safeyolo-proxy" in result.output
    assert "/owned/ready.json" in result.output and "9191" in result.output
    command.read_process.assert_called_once_with()
    command.readiness.assert_called_once_with(command.process)


def test_stop_uses_native_process_owner(command):
    command.mocks["is_proxy_running"].return_value = True
    result = command.runner.invoke(app, ["stop"])
    assert result.exit_code == 0, result.output
    command.mocks["_stop_coord_best_effort"].assert_called_once_with()
    command.mocks["stop_proxy"].assert_called_once_with()


def test_stop_all_uses_native_owner_even_with_shared_pid_marker(command, monkeypatch):
    from safeyolo import platform

    command.mocks["is_proxy_running"].return_value = True
    command.mocks["prior_python_proxy_running"].return_value = True
    host = SimpleNamespace(cleanup_all=lambda _agents: None, unload_firewall_rules=lambda: None)
    monkeypatch.setattr(platform, "get_platform", lambda: host)

    result = command.runner.invoke(app, ["stop", "--all"])

    assert result.exit_code == 0, result.output
    command.mocks["prior_python_proxy_running"].assert_not_called()
    command.mocks["stop_proxy"].assert_called_once_with()


def test_prior_python_process_requires_prior_package_for_status_and_stop(command):
    command.mocks["prior_python_proxy_running"].return_value = True
    for arguments in (["status"], ["stop"], ["stop", "--all"]):
        result = command.runner.invoke(app, arguments)
        assert result.exit_code == 1, result.output
        assert "pinned prior package" in result.output
    command.mocks["stop_proxy"].assert_not_called()
    command.mocks["_stop_coord_best_effort"].assert_not_called()
