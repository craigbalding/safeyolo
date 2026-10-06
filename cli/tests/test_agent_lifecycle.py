"""Retained workflow callers delegate to the installed native lifecycle."""

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import tomlkit
from typer import Exit
from typer.testing import CliRunner

from safeyolo import agent_lifecycle as lifecycle
from safeyolo.cli import app


def test_native_inventory_preserves_degraded_runtime_and_terminal_dimensions(monkeypatch):
    observed = {"agent_id": "ag-marker", "name": "marker", "runtime_state": "degraded",
                "control_state": "unavailable", "agent_state": "unknown", "terminal_state": "running"}
    monkeypatch.setattr(lifecycle, "_native_result", lambda _args: {"agents": [observed]})
    assert lifecycle.list_agent_runtimes() == [observed]


def test_missing_native_owner_cannot_start_a_python_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    with pytest.raises(lifecycle.AgentLifecycleError, match="Native CLI is missing"):
        lifecycle.start_native_agent("marker")


@pytest.mark.parametrize("selected_config", [False, True])
def test_workflow_child_uses_the_selected_lock_and_leaves_all_parent_locks_held(tmp_path, monkeypatch, selected_config):
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)
    if selected_config:
        monkeypatch.setenv("SAFEYOLO_NATIVE_CONFIG_PATH", str(tmp_path / "selected.toml"))
    executable = tmp_path / "bin/safeyolo"
    executable.parent.mkdir()
    executable.write_text(
        f"#!{sys.executable}\n"
        "import fcntl,json,os,sys\n"
        "from pathlib import Path\n"
        "root=Path(sys.argv[2]); name=sys.argv[5]\n"
        "assert sys.argv[1]==('--config' if os.environ.get('SAFEYOLO_NATIVE_CONFIG_PATH') else '--root')\n"
        "if sys.argv[1]=='--config':\n"
        "    assert str(root)==os.environ['SAFEYOLO_NATIVE_CONFIG_PATH']\n"
        "    root=root.parent\n"
        "fd=int(os.environ['SAFEYOLO_HOST_SETUP_LOCK_FD'])\n"
        "assert os.fstat(fd).st_ino==(root/'agents'/name/'host-setup.lock').stat().st_ino\n"
        "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
        "(root/'arguments.json').write_text(json.dumps(sys.argv[3:]))\n"
    )
    executable.chmod(0o755)
    with lifecycle._agent_host_setup_lock("marker"), lifecycle._agent_host_setup_lock("other"):
        assert lifecycle.start_native_agent(
            "marker", launch_mode="background", agent_args=["--model", "fixture model", "--literal", "$(marker)"],
        ) == 0
        for name in ("marker", "other"):
            with (tmp_path / "agents" / name / "host-setup.lock").open("r+") as contender:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert json.loads((tmp_path / "arguments.json").read_text()) == [
        "agent", "start", "marker", "--", "--model", "fixture model", "--literal", "$(marker)",
    ]
    assert lifecycle._held_setup_locks() == {}
    for name in ("marker", "other"):
        with (tmp_path / "agents" / name / "host-setup.lock").open("r+") as contender:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_selected_config_cannot_cross_the_workflows_instance_root(tmp_path, monkeypatch):
    root = tmp_path / "original"
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_NATIVE_CONFIG_PATH", str(tmp_path / "other/selected.toml"))
    with lifecycle._agent_host_setup_lock("marker"):
        with pytest.raises(lifecycle.AgentLifecycleError, match="does not belong to instance"):
            lifecycle.stop_agent_by_name("marker")
        with (root / "agents/marker/host-setup.lock").open("r+") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_real_native_workflow_reads_and_stops_the_selected_same_named_agent(tmp_path, monkeypatch, capfd):
    """Set SAFEYOLO_TEST_NATIVE_CLI to a built native CLI for this boundary probe."""
    binary = os.environ.get("SAFEYOLO_TEST_NATIVE_CLI")
    if not binary:
        pytest.skip("requires the built native CLI (SAFEYOLO_TEST_NATIVE_CLI)")
    root = tmp_path / "instance"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    def native(*arguments, config=None):
        selection = ["--config", str(config)] if config else ["--root", str(root)]
        result = subprocess.run([binary, *selection, *arguments], text=True, capture_output=True, check=True)
        return json.loads(result.stdout) if result.stdout.startswith("{") else None
    native("init")
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(Path(binary).resolve())
    default = native("agent", "create", "marker", "--workspace", str(workspace), "--launcher", "supervisor")
    selected = root / "selected.toml"
    document = tomlkit.parse((root / "config.toml").read_text())
    document["policy_file"] = "selected-policy.toml"
    selected.write_text(tomlkit.dumps(document))
    created = native("agent", "create", "marker", "--workspace", str(workspace), "--launcher", "supervisor", config=selected)
    selected_id = created["configuration"]["id"]
    assert selected_id != default["configuration"]["id"]
    before = {path: path.read_bytes() for path in [root / "config.toml", root / "policy.toml", selected, root / "selected-policy.toml"]}
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.setenv("SAFEYOLO_NATIVE_CONFIG_PATH", str(selected))
    assert lifecycle.native_agent_status("marker")["agent_id"] == selected_id
    assert lifecycle.list_agent_runtimes()[0]["agent_id"] == selected_id
    with lifecycle._agent_host_setup_lock("marker"):
        assert lifecycle.stop_agent_by_name("marker")["agent_id"] == selected_id
        with (root / "agents/marker/host-setup.lock").open("r+") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert {path: path.read_bytes() for path in before if path != selected} == {path: contents for path, contents in before.items() if path != selected}
    assert lifecycle.native_agent_status("marker")["agent_id"] == selected_id
    from safeyolo.commands import factory, lab
    observed_ids = []
    def inspect_role(name):
        observed = lifecycle.native_agent_status(name)
        observed_ids.append(observed["agent_id"])
        return observed
    def end_preparation(**_kwargs):
        raise factory.FactoryContractError("reached selected native status before host preparation")
    monkeypatch.setattr(factory, "native_agent_status", inspect_role)
    monkeypatch.setattr(factory, "_run_host_script_for_agent", end_preparation)
    with pytest.raises(factory.FactoryContractError, match="reached selected native status"):
        factory._run_snapshot(tmp_path / "snapshot.json", {"roles": {"owner": {"agent": "marker"}}})
    assert observed_ids == [selected_id]

    document = tomlkit.parse(selected.read_text())
    document["agent_launcher"] = {"default": "selected-invalid-launcher"}
    # Remove the per-agent override so Lab reaches this selected host default.
    policy = root / "selected-policy.toml"
    selected_policy = tomlkit.parse(policy.read_text())
    del selected_policy["agents"]["marker"]["launcher"]
    policy.write_text(tomlkit.dumps(selected_policy))
    selected.write_text(tomlkit.dumps(document))
    # Lab selects sandbox-only, so its unused default launcher does not block it.
    # A missing workspace fails in the selected policy before any proxy/backend effect.
    selected_policy["agents"]["marker"]["folder"] = str(tmp_path / "selected-missing-workspace")
    policy.write_text(tomlkit.dumps(selected_policy))
    with pytest.raises(Exit) as rejected:
        lab._start_agent("marker")
    assert rejected.value.exit_code == 1
    assert "No such file or directory" in capfd.readouterr().err
    assert not (root / "logs/proxy.log").exists()
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH")
    assert lifecycle.native_agent_status("marker")["agent_id"] == default["configuration"]["id"]


@pytest.mark.parametrize(("options", "expected"), [
    ({}, ["--foreground"]),
    ({"launch_mode": "sandbox", "dangerously_allow_unowned": True},
     ["--sandbox-only", "--dangerously-allow-unowned"]),
    ({"launch_mode": "background", "agent_args": []}, ["--"]),
])
def test_native_start_preserves_local_launch_selection_and_empty_argument_override(monkeypatch, options, expected):
    calls = []
    def invoke(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 19)
    monkeypatch.setattr(lifecycle, "_native_cli", invoke)
    assert lifecycle.start_native_agent("marker", **options) == 19
    assert calls == [(["agent", "start", "marker", *expected], {"setup_name": "marker"})]


def test_native_failure_does_not_become_stopped_or_trigger_python_cleanup(monkeypatch):
    monkeypatch.setattr(lifecycle, "_native_cli", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 1, "", "runtime identity is unknown"))
    with pytest.raises(lifecycle.AgentLifecycleError, match="runtime identity is unknown"):
        lifecycle.stop_agent_by_name("marker")


@pytest.mark.parametrize("output", ["{", "[]", "{}", '{"agents":false}', '{"agents":[false]}'])
def test_incomplete_native_inventory_is_an_error(monkeypatch, output):
    monkeypatch.setattr(lifecycle, "_native_cli", lambda *_args, **_kwargs:
                        subprocess.CompletedProcess([], 0, output, ""))
    with pytest.raises(lifecycle.AgentLifecycleError):
        lifecycle.list_agent_runtimes()


def test_retained_command_forwards_native_start_arguments_and_uses_start_verb(monkeypatch):
    calls = []
    def invoke(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 9)
    monkeypatch.setattr(lifecycle, "_native_cli", invoke)
    result = CliRunner().invoke(app, ["agent", "start", "marker", "--foreground", "--", "argument with spaces"])
    assert result.exit_code == 9, result.output
    assert calls == [(["agent", "start", "marker", "--foreground", "--", "argument with spaces"], {"setup_name": "marker"})]
    absent = CliRunner().invoke(app, ["agent", "run", "marker"])
    assert absent.exit_code != 0
    assert len(calls) == 1


def test_package_status_keeps_native_unknown_runtime_without_proxy(tmp_path, monkeypatch, capfd):
    """Exercise the native owner with missing proxy/listener and damaged runtime evidence."""
    binary = os.environ.get("SAFEYOLO_TEST_NATIVE_CLI")
    if not binary:
        pytest.skip("requires the built native CLI (SAFEYOLO_TEST_NATIVE_CLI)")
    root = tmp_path / "instance"
    root.mkdir()
    command = [str(Path(binary).resolve()), "--root", str(root)]
    subprocess.run([*command, "init"], check=True, capture_output=True)
    (root / "bin").mkdir()
    (root / "bin/safeyolo").symlink_to(Path(binary).resolve())
    subprocess.run([*command, "agent", "create", "marker", "--workspace", str(tmp_path)],
                   check=True, capture_output=True)
    evidence = root / "agents/marker/runtime.json"
    evidence.parent.mkdir(exist_ok=True)
    evidence.write_text("{}")
    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(root))
    monkeypatch.delenv("SAFEYOLO_NATIVE_CONFIG_PATH", raising=False)

    from safeyolo.commands.doctor import _check_running_agents
    from safeyolo.commands.lifecycle import status

    with pytest.raises(Exit) as exited:
        status()
    assert exited.value.exit_code == 0
    observed = json.loads(capfd.readouterr().out)
    assert observed["proxy_state"] == "unavailable"
    assert observed["agents"][0]["runtime_state"] == "unknown"
    assert observed["agents"][0]["control_state"] == "unknown"
    assert observed["agents"][0]["proxy_attachment"]["state"] == "absent"
    diagnosed = json.loads(subprocess.check_output([*command, "agent", "diagnostics", "marker"], text=True))
    assert diagnosed["runtime_state"] == "unknown"
    assert diagnosed["proxy_state"] == "unavailable"
    assert diagnosed["exec"] is False
    check = _check_running_agents()
    assert check.status == "warn"
    assert "runtime=unknown, control=unknown" in check.message
    assert "diagnostics" in check.remediation
    assert evidence.read_text() == "{}"


def test_package_bulk_stop_uses_native_degraded_inventory_and_preserves_refusal(tmp_config_dir, monkeypatch):
    from safeyolo.commands import lifecycle as commands

    observed = [{"name": "degraded", "runtime_state": "degraded"},
                {"name": "unknown", "runtime_state": "unknown"},
                {"name": "stopped", "runtime_state": "stopped"}]
    monkeypatch.setattr(lifecycle, "list_agent_runtimes", lambda: observed)
    stopped, proxy_stops = [], []
    monkeypatch.setattr(lifecycle, "stop_agent_by_name", stopped.append)
    monkeypatch.setattr(commands, "_stop_coord_best_effort", lambda: None)
    monkeypatch.setattr(commands, "is_proxy_running", lambda: True)
    monkeypatch.setattr(commands, "stop_proxy", lambda: proxy_stops.append(True))
    commands.stop_all()
    assert stopped == ["degraded", "unknown"]
    assert proxy_stops == [True]

    def refused(name):
        raise lifecycle.AgentLifecycleError(f"unverified backend identity for {name}")

    proxy_stops.clear()
    monkeypatch.setattr(lifecycle, "stop_agent_by_name", refused)
    with pytest.raises(Exit) as exited:
        commands.stop_all()
    assert exited.value.exit_code == 1
    assert proxy_stops == []


@pytest.mark.parametrize("alias", ["run", "diag", "vm", "config", "shell", "attach", "remove"])
def test_replaced_python_commands_cannot_invoke_a_lifecycle_owner(monkeypatch, alias):
    from safeyolo.cli import app

    invoked = []
    monkeypatch.setattr(lifecycle, "_native_cli", lambda *args, **kwargs: invoked.append(args))
    result = CliRunner().invoke(app, ["agent", alias, "marker"])
    assert result.exit_code != 0
    assert "No such command" in result.output
    assert invoked == []
