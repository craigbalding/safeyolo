"""Tests for SafeYolo's private tmux lifecycle adapter."""

import shlex
import subprocess
from pathlib import Path
from unittest.mock import call, patch

import pytest

from safeyolo.traffic_session import find_private_tmux, session_process_id, start_session


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

    with patch(
        "safeyolo.traffic_session.shutil.which",
        return_value="/usr/bin/tmux",
        autospec=True,
    ):
        assert find_private_tmux() == binary


def test_start_uses_private_socket_and_shell_quotes_command(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with (
        patch(
            "safeyolo.traffic_session.session_exists",
            return_value=False,
            autospec=True,
        ),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            return_value=completed,
            autospec=True,
        ) as run,
    ):
        assert start_session(["python", "-m", "module", "value with spaces"], tmux=tmux) is None

    assert run.call_count == 3
    respawn = run.call_args_list[2].args[0]
    assert respawn[:5] == [
        str(tmux),
        "-S",
        str(tmp_path / "data" / "traffic-tmux.sock"),
        "-f",
        "/dev/null",
    ]
    assert respawn[5:-1] == ["respawn-pane", "-k", "-t", "safeyolo-traffic:0.0"]
    assert respawn[-1] == "python -m module 'value with spaces'"


def test_start_cleans_up_session_after_configuration_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch(
            "safeyolo.traffic_session.session_exists",
            return_value=False,
            autospec=True,
        ),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            side_effect=[subprocess.CompletedProcess([], 0), subprocess.CalledProcessError(1, "tmux")],
            autospec=True,
        ),
        patch(
            "safeyolo.traffic_session.stop_session",
            autospec=True,
        ) as stop,
    ):
        with pytest.raises(subprocess.CalledProcessError):
            start_session(["command"], tmux=tmux)

    assert stop.call_args == call(tmux)


def test_start_reaps_dead_retained_session_before_recreating(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch(
            "safeyolo.traffic_session.session_exists",
            return_value=True,
            autospec=True,
        ),
        patch(
            "safeyolo.traffic_session.session_process_alive",
            return_value=False,
            autospec=True,
        ),
        patch(
            "safeyolo.traffic_session.stop_session",
            autospec=True,
        ) as stop,
        patch(
            "safeyolo.traffic_session.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0),
            autospec=True,
        ),
    ):
        start_session(["command"], tmux=tmux)

    stop.assert_called_once_with(tmux)


def test_start_refuses_live_session(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch(
            "safeyolo.traffic_session.session_exists",
            return_value=True,
            autospec=True,
        ),
        patch(
            "safeyolo.traffic_session.session_process_alive",
            return_value=True,
            autospec=True,
        ),
        pytest.raises(RuntimeError, match="already running"),
    ):
        start_session(["command"], tmux=tmux)


def test_start_exec_owns_the_pane_without_changing_argument_boundaries(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    command = ["/owned path/proxy", "", "value's suffix", "semi;colon", "$(owned)"]
    env = {"OWNED_SETTING": "value"}
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="2468\n", stderr=""),
            autospec=True,
        ) as run,
    ):
        assert start_session(command, tmux=tmux, env=env, exec_command=True) == 2468

    assert run.call_count == 4
    respawn = run.call_args_list[2]
    assert respawn.args[0][-1].startswith("exec ")
    assert shlex.split(respawn.args[0][-1]) == ["exec", *command]
    assert all(invocation.kwargs["env"] is env for invocation in run.call_args_list[:3])
    query = run.call_args_list[3]
    assert query.args[0][5:] == ["display-message", "-p", "-t", "safeyolo-traffic:0.0", "#{pane_pid}"]
    assert query.kwargs["check"] is False


def test_session_process_id_reads_live_status_and_pid_in_one_query(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with patch(
        "safeyolo.traffic_session.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, stdout="0 2468\n", stderr=""),
        autospec=True,
    ) as run:
        assert session_process_id(tmux) == 2468

    run.assert_called_once_with(
        [
            str(tmux),
            "-S",
            str(tmp_path / "data" / "traffic-tmux.sock"),
            "-f",
            "/dev/null",
            "display-message",
            "-p",
            "-t",
            "safeyolo-traffic:0.0",
            "#{pane_dead} #{pane_pid}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_start_passes_cwd_as_one_tmux_argument_without_shell_quoting(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    cwd = tmp_path / "owner's workspace; literal"
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout="2468\n", stderr=""),
            autospec=True,
        ) as run,
    ):
        assert start_session(["proxy", "relative config.json"], tmux=tmux, exec_command=True, cwd=cwd) == 2468

    assert run.call_count == 4
    assert run.call_args_list[2].args[0][5:] == [
        "respawn-pane",
        "-k",
        "-t",
        "safeyolo-traffic:0.0",
        "-c",
        str(cwd),
        "exec proxy 'relative config.json'",
    ]


@pytest.mark.parametrize(
    ("returncode", "output"),
    [
        (1, "0 2468\n"),
        (0, "1 2468\n"),
        (0, ""),
        (0, "0"),
        (0, "0 2468 extra"),
        (0, "invalid 2468"),
        (0, "0 invalid"),
        (0, "0 -2"),
        (0, "0 0"),
        (0, "0 1"),
        (0, "0 +2"),
        (0, "0 2_468"),
        (0, "0 ٢٤٦٨"),
    ],
)
def test_session_process_id_rejects_missing_dead_or_invalid_pane(returncode, output):
    with patch(
        "safeyolo.traffic_session.subprocess.run",
        return_value=subprocess.CompletedProcess([], returncode, stdout=output, stderr=""),
        autospec=True,
    ) as run:
        assert session_process_id(Path("/owned/tmux")) is None
    assert run.call_count == 1


def test_session_process_id_contains_query_os_error():
    with patch("safeyolo.traffic_session.subprocess.run", side_effect=FileNotFoundError, autospec=True):
        assert session_process_id(Path("/owned/tmux")) is None


def test_session_process_id_does_not_hide_unexpected_query_failure():
    with (
        patch("safeyolo.traffic_session.subprocess.run", side_effect=RuntimeError("owned failure"), autospec=True),
        pytest.raises(RuntimeError, match="owned failure"),
    ):
        session_process_id(Path("/owned/tmux"))


@pytest.mark.parametrize("output", ["", "not a PID", "0", "1", "-2", "+2", "2_468", "٢٤٦٨", "2468 9999"])
def test_exec_launch_with_unknown_pid_keeps_its_console(tmp_path, monkeypatch, output):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout=output, stderr=""),
            autospec=True,
        ) as run,
        patch("safeyolo.traffic_session.stop_session", autospec=True) as stop,
    ):
        assert start_session(["owned-proxy"], tmux=Path("/owned/tmux"), exec_command=True) is None
    assert run.call_count == 4
    stop.assert_not_called()


@pytest.mark.parametrize(
    "query_failure", [OSError("owned query failure"), subprocess.CompletedProcess([], 1, stdout="2468", stderr="")]
)
def test_exec_pid_query_failure_does_not_kill_the_launched_pane(tmp_path, monkeypatch, query_failure):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    responses = [subprocess.CompletedProcess([], 0, stdout="", stderr="")] * 3
    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True),
        patch("safeyolo.traffic_session.subprocess.run", side_effect=[*responses, query_failure], autospec=True) as run,
        patch("safeyolo.traffic_session.stop_session", autospec=True) as stop,
    ):
        assert start_session(["owned-proxy"], tmux=Path("/owned/tmux"), exec_command=True) is None
    assert run.call_count == 4
    stop.assert_not_called()
