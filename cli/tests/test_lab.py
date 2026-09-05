"""Regression tests for the first-class SafeYolo Lab lifecycle."""

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

from safeyolo.cli import app
from safeyolo.commands.lab import (
    LAB_EVIDENCE_ROOT,
    LAB_SCHEMA,
    _guest_command,
    _guest_status,
    _has_verified_teardown_evidence,
    _new_state,
    _print_status,
    _proposed_name,
    _read_state,
    _select_agent,
    _start_agent,
    _write_state,
    is_compatible_lab,
    is_lab_managed,
)


def _managed(host_script: str = "@codex", **extra):
    metadata = {
        "folder": "/tmp/project",
        "host_script": host_script,
        "lab_managed": True,
        "lab_schema": LAB_SCHEMA,
        "lab_backend": "codex",
    }
    metadata.update(extra)
    return metadata


def test_lab_requires_explicit_management_and_compatible_backend():
    assert is_lab_managed(_managed())
    assert not is_lab_managed({"lab_managed": 1})
    assert is_compatible_lab(_managed())
    assert is_compatible_lab(_managed("/opt/codex-host-setup.sh"))
    assert not is_compatible_lab(_managed(lab_backend="claude"))
    assert not is_compatible_lab(_managed(lab_schema=2))
    assert not is_compatible_lab({"lab_managed": True, "lab_backend": "codex"})


def test_proposed_agent_name_is_deterministic_and_does_not_collide(tmp_path, monkeypatch):
    configured = {
        "safeyolo-lab": {},
        "safeyolo-lab-2": {},
        "unrelated": {},
    }
    monkeypatch.setattr("safeyolo.commands.lab.load_all_agents", lambda: configured)
    monkeypatch.setattr("safeyolo.commands.lab.get_agents_dir", lambda: tmp_path)
    (tmp_path / "safeyolo-lab-3").mkdir()

    assert _proposed_name() == "safeyolo-lab-4"
    assert configured == {
        "safeyolo-lab": {},
        "safeyolo-lab-2": {},
        "unrelated": {},
    }


def test_multiple_lab_agents_are_selected_by_sorted_visible_choice(monkeypatch):
    agents = {
        "z-lab": _managed(),
        "a-lab": _managed(),
    }
    monkeypatch.setattr("safeyolo.commands.lab.load_all_agents", lambda: agents)
    monkeypatch.setattr("safeyolo.commands.lab.typer.prompt", lambda *_args, **_kwargs: 1)

    selected = _select_agent(None, "codex")

    assert selected is not None
    assert selected[0] == "a-lab"


def test_state_is_private_and_records_objective_before_mutation(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    state = _new_state("safeyolo-lab", tmp_path, "codex", "test a reversible fault")

    path = _write_state("safeyolo-lab", state)

    assert path == config_dir / "labs" / "safeyolo-lab" / "lab-state.json"
    assert _read_state("safeyolo-lab")["objective"] == "test a reversible fault"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert not (config_dir / "agents" / "safeyolo-lab").exists()


def test_lab_boot_uses_existing_agent_lifecycle_without_starting_codex_command():
    with patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True) as run_agent:
        _start_agent("safeyolo-lab")

    assert run_agent.call_args.kwargs == {
        "yolo": True,
        "dangerously_allow_unowned": False,
        "detach": True,
        "no_snapshot": True,
        "rename_tmux_window": False,
        "skip_configured_command": True,
    }


def test_status_reports_stopped_lab_without_starting_or_failing():
    platform = SimpleNamespace(is_sandbox_running=lambda _name: False)
    metadata = _managed()

    assert _print_status("safeyolo-lab", metadata, platform, as_json=False) == 0


def test_status_json_has_no_managed_agent_when_inventory_is_empty(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    runner = CliRunner()

    result = runner.invoke(app, ["lab", "--status", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == {"managed": False, "agents": []}


def test_status_does_not_require_the_guest_controller_to_be_alive(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    process = SimpleNamespace(
        communicate=lambda timeout: (
            '{"agent":"safeyolo-lab","session":"lab","session_exists":true,"owned":true,"controller_alive":false}',
            "",
        )
    )
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: True,
        popen_in_sandbox=lambda *_args, **_kwargs: process,
    )

    with (
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
    ):
        result = CliRunner().invoke(app, ["lab", "--status", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["guest"]["controller_alive"] is False
    assert payload["guest_status"]["state"] == "controller-dead"


def test_status_json_reports_wrong_identity_or_impossible_state_as_unknown(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    statuses = [
        '{"agent":"other-lab","session":"lab","session_exists":false,"owned":false,"controller_alive":false}',
        '{"agent":"safeyolo-lab","session":"other","session_exists":false,"owned":false,"controller_alive":false}',
        '{"agent":"safeyolo-lab","session":"lab","session_exists":false,"owned":true,"controller_alive":true}',
    ]

    for status in statuses:
        process = SimpleNamespace(communicate=lambda timeout, status=status: (status, ""))
        platform = SimpleNamespace(
            is_sandbox_running=lambda _name: True,
            popen_in_sandbox=lambda *_args, **_kwargs: process,
        )
        with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
            result = CliRunner().invoke(app, ["lab", "--status", "--json"])

        assert result.exit_code == 2
        payload = json.loads(result.stdout)
        assert payload["guest_status"]["state"] == "unknown"
        assert payload["guest_status"]["diagnostic"]

        process = SimpleNamespace(communicate=lambda timeout, status=status: (status, ""))
        platform = SimpleNamespace(
            is_sandbox_running=lambda _name: True,
            popen_in_sandbox=lambda *_args, **_kwargs: process,
        )
        with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
            result = CliRunner().invoke(app, ["lab", "--status"])

        assert result.exit_code == 2
        assert "Guest status: unknown" in result.stdout
        assert "Diagnostic:" in result.stdout


def test_invalid_guest_status_does_not_drive_lifecycle_actions(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    invalid_status = (
        '{"agent":"safeyolo-lab","session":"lab",'
        '"session_exists":false,"owned":true,"controller_alive":true}'
    )

    for action in ([], ["--recover"], ["--relaunch"], ["--teardown"]):
        _write_state(
            "safeyolo-lab",
            _new_state("safeyolo-lab", tmp_path, "codex", "inspect a bounded fault"),
        )
        commands = []
        process = SimpleNamespace(communicate=lambda timeout: (invalid_status, ""))
        platform = SimpleNamespace(
            is_sandbox_running=lambda _name: True,
            popen_in_sandbox=lambda *args, **kwargs: commands.append((args, kwargs)) or process,
            exec_in_sandbox=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("invalid status reached attach")
            ),
            stop_sandbox=lambda _name: (_ for _ in ()).throw(
                AssertionError("invalid status reached teardown")
            ),
        )

        with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
            result = CliRunner().invoke(app, ["lab", "--agent", "safeyolo-lab", *action])

        assert result.exit_code == 2
        assert [command[0][1] for command in commands] == ["safeyolo-lab --status --json"]
        assert _read_state("safeyolo-lab")["phase"] == "prepared"


def test_status_json_reports_unknown_guest_status_and_fails_closed(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    process = SimpleNamespace(
        communicate=lambda timeout: ("synthetic diagnostic", ""),
    )
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: True,
        popen_in_sandbox=lambda *_args, **_kwargs: process,
    )

    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        result = CliRunner().invoke(app, ["lab", "--status", "--json"])

    assert result.exit_code == 2
    payload = json.loads(result.stdout)
    assert payload["guest"] == {}
    assert payload["guest_status"] == {
        "diagnostic": "synthetic diagnostic",
        "state": "unknown",
    }


def test_guest_status_reaps_real_subprocess_timeout():
    events = []

    class TimedOutProcess:
        def communicate(self, timeout):
            raise subprocess.TimeoutExpired(["safeyolo-lab", "--status"], timeout)

        def kill(self):
            events.append("kill")

        def wait(self, timeout):
            events.append(("wait", timeout))

    platform = SimpleNamespace(
        popen_in_sandbox=lambda *_args, **_kwargs: TimedOutProcess(),
    )

    status, diagnostic = _guest_status(platform, "safeyolo-lab")

    assert status == {}
    assert "30 second deadline" in diagnostic
    assert events == ["kill", ("wait", 5)]


def test_guest_command_reaps_real_subprocess_timeout():
    events = []

    class TimedOutProcess:
        def communicate(self, timeout):
            raise subprocess.TimeoutExpired(["safeyolo-lab", "--teardown"], timeout)

        def kill(self):
            events.append("kill")

        def wait(self, timeout):
            events.append(("wait", timeout))

    platform = SimpleNamespace(
        popen_in_sandbox=lambda *_args, **_kwargs: TimedOutProcess(),
    )

    result = _guest_command(platform, "safeyolo-lab", "safeyolo-lab --teardown")

    assert result == (124, "", "The guest Lab command exceeded its 60 second deadline.")
    assert events == ["kill", ("wait", 5)]


def test_recovery_without_a_managed_lab_does_not_create_one(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))

    result = CliRunner().invoke(app, ["lab", "--recover"])

    assert result.exit_code == 1
    assert "Start a Lab first" in result.stdout
    assert not (config_dir / "agents").exists()


def test_active_owned_lab_reattaches_without_reasking_objective(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    process = SimpleNamespace(
        communicate=lambda timeout: (
            '{"agent":"safeyolo-lab","session":"lab","session_exists":true,"owned":true,"controller_alive":true}',
            "",
        )
    )
    attach = SimpleNamespace(
        is_sandbox_running=lambda _name: True,
        popen_in_sandbox=lambda *_args, **_kwargs: process,
        exec_in_sandbox=lambda *args, **kwargs: 0,
    )

    with patch("safeyolo.platform.get_platform", return_value=attach, autospec=True):
        result = CliRunner().invoke(app, ["lab", "--agent", "safeyolo-lab"])

    assert result.exit_code == 0
    assert "objective" not in result.stdout.lower()


def test_recovery_of_stopped_lab_reuses_recorded_objective(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    _write_state(
        "safeyolo-lab",
        _new_state("safeyolo-lab", tmp_path, "codex", "inspect a bounded fault"),
    )
    process = SimpleNamespace(
        communicate=lambda timeout: (
            '{"agent":"safeyolo-lab","session":"lab","session_exists":false,"owned":false,"controller_alive":false}',
            "",
        )
    )
    attached = []
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: False,
        popen_in_sandbox=lambda *_args, **_kwargs: process,
        exec_in_sandbox=lambda *args, **kwargs: attached.append((args, kwargs)) or 0,
    )

    with (
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch("safeyolo.commands.lab._start_agent", autospec=True) as start_agent,
    ):
        result = CliRunner().invoke(app, ["lab", "--agent", "safeyolo-lab", "--recover"])

    assert result.exit_code == 0
    start_agent.assert_called_once_with("safeyolo-lab")
    assert attached[0][0][1] == "safeyolo-lab --objective 'inspect a bounded fault'"


def test_teardown_captures_evidence_and_can_retain_the_agent(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    _write_state(
        "safeyolo-lab",
        _new_state("safeyolo-lab", tmp_path, "codex", "inspect a bounded fault"),
    )
    capture_dir = config_dir / "agents" / "safeyolo-lab" / "home" / ".safeyolo" / "lab-evidence" / "test-capture"
    capture_dir.mkdir(parents=True)
    (capture_dir / "capture-status.txt").write_text("status=complete\n", encoding="utf-8")
    (capture_dir / "manifest.jsonl").write_text("{}\n", encoding="utf-8")
    (capture_dir / "SHA256SUMS").write_text("", encoding="utf-8")
    stopped = []
    commands = []

    def communicate(timeout):
        if commands[-1][0][1] == "safeyolo-lab --status --json":
            return '{"agent":"safeyolo-lab","session":"lab","session_exists":true,"owned":true,"controller_alive":true}', ""
        return "Lab session removed after redacted evidence capture: /home/agent/.safeyolo/lab-evidence/test-capture", ""

    process = SimpleNamespace(communicate=communicate, returncode=0)
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: True,
        popen_in_sandbox=lambda *args, **kwargs: commands.append((args, kwargs)) or process,
        stop_sandbox=lambda name: stopped.append(name),
    )

    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        result = CliRunner().invoke(
            app,
            ["lab", "--agent", "safeyolo-lab", "--teardown", "--keep-agent"],
        )

    assert result.exit_code == 0
    assert commands[-1][0][1] == "safeyolo-lab --teardown"
    assert stopped == []
    assert _read_state("safeyolo-lab")["phase"] == "teardown-complete"

    alias = capture_dir.parent / "capture-alias"
    alias.symlink_to(capture_dir, target_is_directory=True)
    assert not _has_verified_teardown_evidence(
        "safeyolo-lab", f"{LAB_EVIDENCE_ROOT}/capture-alias"
    )


def test_teardown_without_verified_evidence_stays_incomplete(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    _write_state(
        "safeyolo-lab",
        _new_state("safeyolo-lab", tmp_path, "codex", "inspect a bounded fault"),
    )
    commands = []

    def communicate(timeout):
        if commands[-1][0][1] == "safeyolo-lab --status --json":
            return '{"agent":"safeyolo-lab","session":"lab","session_exists":true,"owned":true,"controller_alive":true}', ""
        return "Lab session removed after redacted evidence capture: /home/agent/.safeyolo/lab-evidence/missing", ""

    process = SimpleNamespace(communicate=communicate, returncode=0)
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: True,
        popen_in_sandbox=lambda *args, **kwargs: commands.append((args, kwargs)) or process,
    )

    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        result = CliRunner().invoke(
            app,
            ["lab", "--agent", "safeyolo-lab", "--teardown", "--keep-agent"],
        )

    assert result.exit_code == 2
    state = _read_state("safeyolo-lab")
    assert state["phase"] == "teardown-incomplete"
    assert state["evidence_status"] == "not-captured"
    assert "verified evidence" in state["teardown_result"]


def test_teardown_without_live_guest_records_no_capture(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    _write_state(
        "safeyolo-lab",
        _new_state("safeyolo-lab", tmp_path, "codex", "inspect a bounded fault"),
    )
    commands = []
    stopped = []
    process = SimpleNamespace(
        communicate=lambda timeout: (
            '{"agent":"safeyolo-lab","session":"lab","session_exists":false,"owned":false,"controller_alive":false}',
            "",
        ),
    )
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: True,
        popen_in_sandbox=lambda *args, **kwargs: commands.append((args, kwargs)) or process,
        stop_sandbox=lambda name: stopped.append(name),
    )

    with patch("safeyolo.platform.get_platform", return_value=platform, autospec=True):
        result = CliRunner().invoke(app, ["lab", "--agent", "safeyolo-lab", "--teardown"])

    assert result.exit_code == 0
    assert [command[0][1] for command in commands] == ["safeyolo-lab --status --json"]
    assert stopped == ["safeyolo-lab"]
    state = _read_state("safeyolo-lab")
    assert state["phase"] == "teardown-complete"
    assert state["evidence_status"] == "not-captured-no-live-session"
    assert "no guest resources were removed" in state["teardown_result"]


def test_stopped_teardown_does_not_boot_or_probe_the_guest(tmp_path, monkeypatch):
    config_dir = tmp_path / ".safeyolo"
    config_dir.mkdir()
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(
        "safeyolo.commands.lab.load_all_agents",
        lambda: {"safeyolo-lab": _managed()},
    )
    _write_state(
        "safeyolo-lab",
        _new_state("safeyolo-lab", tmp_path, "codex", "inspect a bounded fault"),
    )
    platform = SimpleNamespace(
        is_sandbox_running=lambda _name: False,
        popen_in_sandbox=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("stopped teardown probed the guest")
        ),
    )

    with (
        patch("safeyolo.platform.get_platform", return_value=platform, autospec=True),
        patch("safeyolo.commands.lab._start_agent", autospec=True) as start_agent,
    ):
        result = CliRunner().invoke(
            app,
            ["lab", "--agent", "safeyolo-lab", "--teardown"],
        )

    assert result.exit_code == 0
    start_agent.assert_not_called()
    state = _read_state("safeyolo-lab")
    assert state["phase"] == "teardown-complete"
    assert state["evidence_status"] == "not-captured-no-live-guest"
    assert "no guest session was inspected or removed" in state["teardown_result"]
