"""Backend-aware lifecycle UX with owned config and mocked process boundaries."""

from types import SimpleNamespace
from unittest.mock import create_autospec

import pytest
import yaml
from typer.testing import CliRunner

from safeyolo import rust_proxy
from safeyolo.cli import app
from safeyolo.commands import lifecycle, policy
from safeyolo.platform import get_platform


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
        "check_running_backend",
        "is_proxy_running",
        "start_proxy",
        "stop_proxy",
        "wait_for_healthy",
        "check_guest_images",
        "missing_guest_images",
        "_start_coord_best_effort",
        "_web_tailnet_runtime",
        "write_event",
        "get_api",
    ):
        mock = create_autospec(getattr(lifecycle, name), spec_set=True)
        monkeypatch.setattr(lifecycle, name, mock)
        mocks[name] = mock
    mocks["check_running_backend"].return_value = False
    mocks["is_proxy_running"].return_value = False
    mocks["wait_for_healthy"].return_value = True
    mocks["check_guest_images"].return_value = True
    mocks["_start_coord_best_effort"].return_value = "healthy"
    mocks["_web_tailnet_runtime"].return_value = {}
    preflight = create_autospec(policy.assert_policy_has_permissions, spec_set=True)
    monkeypatch.setattr(policy, "assert_policy_has_permissions", preflight)
    config_path = config_dir / "config.yaml"

    def configure(backend="rust", test_enabled=True):
        proxy = {"port": 8123, "admin_port": 9191}
        if backend is not None:
            proxy["backend"] = backend
        if backend == "rust":
            proxy["rust_config"] = "owned-native.json"
        config = {"proxy": proxy, "test": {"enabled": test_enabled, "sinkhole_router": "owned-sinkhole.py"}}
        config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return config_path.read_bytes()

    configure()
    return SimpleNamespace(
        runner=CliRunner(),
        mocks=mocks,
        preflight=preflight,
        config_path=config_path,
        configure=configure,
    )


def test_rust_start_uses_native_owner_and_preserves_python_test_setting(command):
    before = command.config_path.read_bytes()
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 0, result.output
    command.preflight.assert_not_called()
    command.mocks["check_running_backend"].assert_called_once_with()
    command.mocks["start_proxy"].assert_called_once_with()
    command.mocks["wait_for_healthy"].assert_called_once_with(timeout=30)
    for name in ("check_guest_images", "missing_guest_images", "_start_coord_best_effort", "_web_tailnet_runtime"):
        command.mocks[name].assert_not_called()
    assert command.config_path.read_bytes() == before
    assert "Rust native backend" in result.output and "owned-native.json" in result.output
    assert "localhost" not in result.output and "safeyolo agent add" not in result.output
    assert "incomplete." in result.output and "WebMITM:" not in result.output


def test_first_run_bootstrap_persists_absolute_native_config_path(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

    lifecycle._bootstrap_config(config_dir)

    config = yaml.safe_load((config_dir / "config.yaml").read_text())
    assert config["proxy"]["backend"] == "rust"
    assert config["proxy"]["rust_config"] == str(config_dir / "data" / "native.json")


@pytest.mark.parametrize("args", [["--test"], ["--dev"], ["--flow-cache", "9"], ["--flow-cache-bytes", "90"]])
def test_rust_rejects_python_flags_before_preflight_or_mutation(command, args):
    before = command.config_path.read_bytes()
    result = command.runner.invoke(app, ["start", *args])
    assert result.exit_code == 1, result.output
    assert args[0] in result.output and "proxy.rust_config" in result.output
    assert command.config_path.read_bytes() == before
    command.preflight.assert_not_called()
    for name in ("check_running_backend", "start_proxy", "wait_for_healthy", "_start_coord_best_effort"):
        command.mocks[name].assert_not_called()


def test_rust_up_no_wait_still_uses_central_start_readiness(command):
    result = command.runner.invoke(app, ["up", "--no-wait"])
    assert result.exit_code == 0, result.output
    command.mocks["start_proxy"].assert_called_once_with()
    command.mocks["wait_for_healthy"].assert_not_called()
    assert "Rust native backend" in result.output


def test_running_rust_skips_launch_and_python_coord(command):
    command.mocks["check_running_backend"].return_value = True
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 0 and "already running" in result.output
    command.mocks["start_proxy"].assert_not_called()
    command.mocks["wait_for_healthy"].assert_not_called()
    command.mocks["_start_coord_best_effort"].assert_not_called()
    command.preflight.assert_not_called()


@pytest.mark.parametrize("backend", ["rust", "python"])
def test_backend_mismatch_stops_before_start_or_config_mutation(command, backend):
    before = command.configure(backend=backend)
    command.preflight.side_effect = RuntimeError("unrelated Python policy is invalid")
    command.mocks["check_running_backend"].side_effect = RuntimeError(
        "Running python backend; stop it before selecting rust"
    )
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1 and "stop it before selecting rust" in result.output
    command.preflight.assert_not_called()
    command.mocks["start_proxy"].assert_not_called()
    command.mocks["wait_for_healthy"].assert_not_called()
    command.mocks["_start_coord_best_effort"].assert_not_called()
    assert command.config_path.read_bytes() == before


def test_invalid_selector_reports_error_before_python_preflight(command):
    before = command.configure(backend="unknown")
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1 and "backend" in result.output
    command.preflight.assert_not_called()
    command.mocks["check_running_backend"].assert_not_called()
    command.mocks["start_proxy"].assert_not_called()
    assert command.config_path.read_bytes() == before


def test_rust_failed_health_stops_and_reports_native_diagnostics(command):
    command.mocks["wait_for_healthy"].return_value = False
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1
    command.mocks["stop_proxy"].assert_called_once_with()
    command.mocks["_start_coord_best_effort"].assert_not_called()
    assert "native launch diagnostics" in result.output and "mitmproxy.log" not in result.output
    details = command.mocks["write_event"].call_args.kwargs["details"]
    assert details == {"phase": "health", "backend": "rust"}


def test_rust_launch_error_is_reported_without_fallback(command):
    command.mocks["start_proxy"].side_effect = RuntimeError("native executable is unavailable")
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 1 and "native executable is unavailable" in result.output
    command.mocks["start_proxy"].assert_called_once_with()
    command.mocks["wait_for_healthy"].assert_not_called()
    command.mocks["_start_coord_best_effort"].assert_not_called()
    assert command.mocks["write_event"].call_args.kwargs["details"]["phase"] == "launch"


def test_explicit_python_keeps_preflight_launch_flags_and_test_mode_reset(command):
    command.configure(backend="python")
    result = command.runner.invoke(app, ["start", "--dev", "--flow-cache", "7", "--flow-cache-bytes", "70"])
    assert result.exit_code == 0, result.output
    command.preflight.assert_called_once_with(command.config_path.parent)
    command.mocks["start_proxy"].assert_called_once_with(
        proxy_port=8123, admin_port=9191, flow_cache=7, flow_cache_bytes=70, dev=True
    )
    command.mocks["wait_for_healthy"].assert_called_once_with(timeout=30, admin_port=9191)
    command.mocks["_start_coord_best_effort"].assert_called_once_with()
    command.mocks["check_guest_images"].assert_called_once_with()
    assert yaml.safe_load(command.config_path.read_text())["test"]["enabled"] is False
    assert "http://localhost:8123" in result.output


def test_python_test_flag_still_persists_enabled_setting(command):
    command.configure(backend="python", test_enabled=False)
    result = command.runner.invoke(app, ["start", "--test", "--no-wait"])
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(command.config_path.read_text())["test"]["enabled"] is True
    command.preflight.assert_called_once_with(command.config_path.parent)
    command.mocks["wait_for_healthy"].assert_not_called()


def test_running_python_still_reconciles_coord(command):
    command.configure(backend="python")
    command.mocks["check_running_backend"].return_value = True
    result = command.runner.invoke(app, ["start"])
    assert result.exit_code == 0 and "already healthy" in result.output
    command.preflight.assert_called_once_with(command.config_path.parent)
    command.mocks["_start_coord_best_effort"].assert_called_once_with()
    command.mocks["start_proxy"].assert_not_called()


@pytest.mark.parametrize("ready", [True, False])
def test_status_uses_live_rust_receipt_after_selection_changes(command, monkeypatch, ready):
    command.configure(backend="python")
    command.mocks["is_proxy_running"].return_value = True
    process = rust_proxy.RustProcess(
        pid=4321,
        start_token="synthetic-owned-start",
        readiness_file="/owned/ready.json",
        admin_port=0,
        admin_token_file=None,
    )
    read_process = create_autospec(rust_proxy.read_process, spec_set=True, return_value=process)
    readiness = create_autospec(
        rust_proxy.readiness,
        spec_set=True,
        return_value={"ready": True, "admin_port": 45678} if ready else None,
    )
    monkeypatch.setattr(rust_proxy, "read_process", read_process)
    monkeypatch.setattr(rust_proxy, "readiness", readiness)
    coord = SimpleNamespace(status=create_autospec(
        lifecycle.coord_nats.status, spec_set=True, return_value={"state": "not-running"}
    ))
    monkeypatch.setattr(lifecycle, "coord_nats", coord)
    platform = create_autospec(get_platform, spec_set=True)
    monkeypatch.setattr("safeyolo.platform.get_platform", platform)
    result = command.runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output
    command.mocks["is_proxy_running"].assert_called_once_with()
    read_process.assert_called_once_with()
    readiness.assert_called_once_with(process)
    assert "Rust development" in result.output and "4321" in result.output
    assert "running" in result.output and "/owned/ready.json" in result.output
    if ready:
        assert "45678" in result.output and "not ready" not in result.output
    else:
        assert "not ready" in result.output and "unavailable until ready" in result.output
    assert "8123" not in result.output and "9191" not in result.output
    assert "WebMITM" not in result.output and "Coord" not in result.output
    for name in ("get_api", "check_guest_images", "_web_tailnet_runtime", "check_running_backend"):
        command.mocks[name].assert_not_called()
    coord.status.assert_not_called()
    platform.assert_not_called()


def test_stopped_status_does_not_consult_rust_receipt(command, monkeypatch):
    read_process = create_autospec(rust_proxy.read_process, spec_set=True)
    monkeypatch.setattr(rust_proxy, "read_process", read_process)
    result = command.runner.invoke(app, ["status"])
    assert result.exit_code == 0 and "not running" in result.output
    read_process.assert_not_called()
    command.mocks["get_api"].assert_not_called()
