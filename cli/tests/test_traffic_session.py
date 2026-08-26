"""Tests for SafeYolo's private tmux lifecycle adapter."""

import subprocess
from pathlib import Path
from unittest.mock import call, patch

import pytest

from safeyolo.traffic_session import find_private_tmux, start_session


def test_explicit_private_tmux_must_be_executable(tmp_path, monkeypatch):
    binary = tmp_path / "tmux"
    binary.write_text("binary")
    monkeypatch.setenv("SAFEYOLO_TMUX_BIN", str(binary))

    with pytest.raises(RuntimeError, match="not executable"):
        find_private_tmux()


def test_config_local_private_tmux_precedes_system(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    binary = tmp_path / "bin" / "safeyolo-tmux"
    binary.parent.mkdir()
    binary.write_text("binary")
    binary.chmod(0o700)

    with patch("safeyolo.traffic_session.shutil.which", return_value="/usr/bin/tmux", autospec=True,):
        assert find_private_tmux() == binary


def test_start_uses_private_socket_and_shell_quotes_command(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True,),
        patch("safeyolo.traffic_session.subprocess.run", return_value=completed, autospec=True,) as run,
    ):
        start_session(["python", "-m", "module", "value with spaces"], tmux=tmux)

    assert run.call_count == 3
    respawn = run.call_args_list[2].args[0]
    assert respawn[:5] == [
        str(tmux),
        "-S",
        str(tmp_path / "data" / "traffic-tmux.sock"),
        "-f",
        "/dev/null",
    ]
    assert respawn[-1] == "python -m module 'value with spaces'"


def test_start_cleans_up_session_after_configuration_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True,),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            side_effect=[subprocess.CompletedProcess([], 0), subprocess.CalledProcessError(1, "tmux")],
        autospec=True,
        ),
        patch("safeyolo.traffic_session.stop_session", autospec=True,) as stop,
    ):
        with pytest.raises(subprocess.CalledProcessError):
            start_session(["command"], tmux=tmux)

    assert stop.call_args == call(tmux)


def test_start_reaps_dead_retained_session_before_recreating(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=True, autospec=True,),
        patch("safeyolo.traffic_session.session_process_alive", return_value=False, autospec=True,),
        patch("safeyolo.traffic_session.stop_session", autospec=True,) as stop,
        patch("safeyolo.traffic_session.subprocess.run", return_value=subprocess.CompletedProcess([], 0), autospec=True,),
    ):
        start_session(["command"], tmux=tmux)

    stop.assert_called_once_with(tmux)


def test_start_refuses_live_session(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=True, autospec=True,),
        patch("safeyolo.traffic_session.session_process_alive", return_value=True, autospec=True,),
        pytest.raises(RuntimeError, match="already running"),
    ):
        start_session(["command"], tmux=tmux)
