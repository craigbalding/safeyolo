"""Tests for SafeYolo's private tmux lifecycle adapter."""

import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from unittest.mock import call, patch

import pytest

from safeyolo.traffic_session import (
    find_private_tmux,
    interrupt_session_process,
    session_process_id,
    start_session,
)


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


def test_private_only_lookup_does_not_mask_missing_runtime_with_system(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("SAFEYOLO_TMUX_BIN", raising=False)
    with patch("safeyolo.traffic_session.shutil.which", return_value="/usr/bin/tmux", autospec=True) as which:
        with pytest.raises(RuntimeError, match="private tmux runtime is missing"):
            find_private_tmux(allow_system=False)
        which.assert_not_called()


def test_private_only_lookup_finds_instance_and_rejects_removed_explicit_runtime(tmp_path, monkeypatch):
    monkeypatch.delenv("SAFEYOLO_TMUX_BIN", raising=False)
    binary = tmp_path / "bin/safeyolo-tmux"
    binary.parent.mkdir()
    binary.write_text("binary")
    binary.chmod(0o755)
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    assert find_private_tmux(allow_system=False) == binary
    monkeypatch.setenv("SAFEYOLO_TMUX_BIN", str(binary))
    binary.unlink()
    with patch("safeyolo.traffic_session.shutil.which", return_value="/usr/bin/tmux", autospec=True):
        with pytest.raises(RuntimeError, match="not executable"):
            find_private_tmux()


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
    def tmux_result(args, **_kwargs):
        if args[5] == "show-options":
            return subprocess.CompletedProcess(args, 1, stdout="", stderr="no server running")
        return subprocess.CompletedProcess(args, 0, stdout="2468\n", stderr="")

    with (
        patch("safeyolo.traffic_session.session_exists", return_value=False, autospec=True),
        patch(
            "safeyolo.traffic_session.subprocess.run",
            side_effect=tmux_result,
            autospec=True,
        ) as run,
    ):
        assert start_session(command, tmux=tmux, env=env, exec_command=True) == 2468

    assert run.call_count == 5
    respawn = run.call_args_list[3]
    assert respawn.args[0][-1].startswith("exec ")
    assert shlex.split(respawn.args[0][-1]) == ["exec", *command]
    assert all(invocation.kwargs["env"] is env for invocation in run.call_args_list[:4])
    query = run.call_args_list[4]
    assert query.args[0][5:] == ["display-message", "-p", "-t", "safeyolo-traffic:0.0", "#{pane_pid}"]
    assert query.kwargs["check"] is False


def test_existing_private_tmux_server_receives_new_and_removed_share(tmp_path, monkeypatch):
    tmux = shutil.which("tmux")
    if tmux is None:
        pytest.skip("tmux is not installed")
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    from safeyolo.traffic_session import session_process_alive, socket_path

    socket_path().parent.mkdir(parents=True)
    base = [tmux, "-S", str(socket_path()), "-f", "/dev/null"]
    old_env = os.environ.copy() | {"SAFEYOLO_COMMAND_CENTRE_SHARE": "local"}

    def observed_share(share, name):
        target = tmp_path / name
        env = os.environ.copy()
        if share is None:
            env.pop("SAFEYOLO_COMMAND_CENTRE_SHARE", None)
        else:
            env["SAFEYOLO_COMMAND_CENTRE_SHARE"] = share
        command = f'printf "%s" "${{SAFEYOLO_COMMAND_CENTRE_SHARE-unset}}" > {shlex.quote(str(target))}'
        start_session(["/bin/sh", "-c", command], tmux=Path(tmux), env=env, exec_command=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (not target.exists() or session_process_alive(Path(tmux))):
            time.sleep(0.05)
        assert target.exists()
        assert not session_process_alive(Path(tmux))
        return target.read_text()

    try:
        subprocess.run([*base, "new-session", "-d", "-s", "keeper", "/bin/sleep 60"],
                       env=old_env, check=True, capture_output=True)
        original = subprocess.run([*base, "show-options", "-gqv", "update-environment"],
                                  check=True, capture_output=True, text=True).stdout
        assert observed_share("tailnet", "tailnet-share") == "tailnet"
        assert observed_share(None, "disabled-share") == "unset"
        restored = subprocess.run([*base, "show-options", "-gqv", "update-environment"],
                                  check=True, capture_output=True, text=True).stdout
        assert restored == original
    finally:
        subprocess.run([*base, "kill-server"], capture_output=True)


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


@pytest.mark.parametrize(
    ("pane", "token"),
    [
        ("1 2468 %4\n", "owned"),
        ("0 2469 %4\n", "owned"),
        ("0 2468 %4\n", "replacement"),
        ("0 2468 invalid\n", "owned"),
    ],
)
def test_tmux_interrupt_refuses_unowned_pane(tmp_path, monkeypatch, pane, token):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    with (
        patch("safeyolo.traffic_session.process_start_token", return_value=token, autospec=True),
        patch("safeyolo.traffic_session.subprocess.run",
              return_value=subprocess.CompletedProcess([], 0, stdout=pane, stderr=""), autospec=True) as run,
        pytest.raises(RuntimeError, match="Cannot verify Rust proxy tmux pane identity"),
    ):
        interrupt_session_process(2468, "owned", tmux=Path("/opt/safeyolo/tmux"))
    run.assert_called_once()


def test_tmux_interrupt_targets_verified_pane_id(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    tmux = Path("/opt/safeyolo/tmux")
    with (
        patch("safeyolo.traffic_session.process_start_token", return_value="owned", autospec=True),
        patch("safeyolo.traffic_session.subprocess.run", side_effect=[
            subprocess.CompletedProcess([], 0, stdout="0 2468 %4\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ], autospec=True) as run,
    ):
        interrupt_session_process(2468, "owned", tmux=tmux)
    assert run.call_count == 2
    assert run.call_args_list[1].args[0] == [
        str(tmux), "-S", str(tmp_path / "data" / "traffic-tmux.sock"), "-f", "/dev/null",
        "send-keys", "-t", "%4", "C-c",
    ]


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
