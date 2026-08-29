"""Persistent primary-workspace updates for ``agent config``."""

import os
from unittest.mock import create_autospec, patch

from safeyolo.agents_store import (
    load_agent,
    mutate_agent,
    remove_agent,
    save_agent,
)
from safeyolo.cli import app
from safeyolo.platform import AgentPlatform


def _setup_agent(config_dir, folder, **extra):
    metadata = {
        "folder": str(folder),
        "host_script": "/host/setup.sh",
        "agent_id": "ag-" + "a" * 32,
        "services": {"github": {"capability": "pull_requests"}},
        **extra,
    }
    save_agent("worker", metadata)
    return metadata


def _platform(*, running: bool):
    platform = create_autospec(AgentPlatform, instance=True, spec_set=True)
    platform.is_sandbox_running.return_value = running
    return platform


class TestAgentConfigFolder:
    def test_stopped_agent_persists_normalized_folder(
        self, cli_runner, tmp_config_dir, tmp_path, monkeypatch
    ):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        _setup_agent(tmp_config_dir, old)
        monkeypatch.chdir(tmp_path)

        platform = _platform(running=False)
        with (
            patch(
                "safeyolo.platform.get_platform",
                return_value=platform,
                autospec=True,
            ),
            patch(
                "safeyolo.commands.agent.write_event", autospec=True
            ) as write_event,
        ):
            result = cli_runner.invoke(
                app, ["agent", "config", "worker", "--folder", "new"]
            )

        assert result.exit_code == 0, result.output
        assert load_agent("worker")["folder"] == str(new.resolve())
        assert "next run" in result.output
        write_event.assert_called_once()
        event = write_event.call_args
        assert event.args[0] == "agent.config_changed"
        assert event.kwargs["details"] == {"changes": ["folder"]}
        assert str(old) not in event.kwargs["summary"]
        assert str(new) not in event.kwargs["summary"]

    def test_running_agent_is_explicitly_next_run_only(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        _setup_agent(tmp_config_dir, old)

        platform = _platform(running=True)
        with patch(
            "safeyolo.platform.get_platform",
            return_value=platform,
            autospec=True,
        ):
            result = cli_runner.invoke(
                app, ["agent", "config", "worker", "--folder", str(new)]
            )

        assert result.exit_code == 0, result.output
        assert load_agent("worker")["folder"] == str(new.resolve())
        assert "running sandbox is unchanged" in result.output
        assert "stop and run" in result.output

    def test_same_folder_is_noop_without_audit(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        folder = tmp_path / "project"
        folder.mkdir()
        before = _setup_agent(tmp_config_dir, folder)

        with patch(
            "safeyolo.commands.agent.write_event", autospec=True
        ) as write_event:
            result = cli_runner.invoke(
                app, ["agent", "config", "worker", "--folder", str(folder)]
            )

        assert result.exit_code == 0, result.output
        assert "unchanged" in result.output
        assert load_agent("worker") == before
        write_event.assert_not_called()

    def test_missing_folder_is_rejected_without_mutation(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        old.mkdir()
        before = _setup_agent(tmp_config_dir, old)

        result = cli_runner.invoke(
            app,
            ["agent", "config", "worker", "--folder", str(tmp_path / "missing")],
        )

        assert result.exit_code == 1
        assert "Folder not found" in result.output
        assert load_agent("worker") == before

    def test_file_is_rejected_as_folder(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        old.mkdir()
        target = tmp_path / "file"
        target.write_text("not a directory")
        before = _setup_agent(tmp_config_dir, old)

        result = cli_runner.invoke(
            app, ["agent", "config", "worker", "--folder", str(target)]
        )

        assert result.exit_code == 1
        assert "Folder not found" in result.output
        assert load_agent("worker") == before

    def test_unowned_folder_requires_explicit_override(
        self, cli_runner, tmp_config_dir, tmp_path, monkeypatch
    ):
        old = tmp_path / "old"
        target = tmp_path / "target"
        old.mkdir()
        target.mkdir()
        _setup_agent(tmp_config_dir, old)
        monkeypatch.setattr(os, "getuid", lambda: target.stat().st_uid + 1)

        denied = cli_runner.invoke(
            app, ["agent", "config", "worker", "--folder", str(target)]
        )
        with patch(
            "safeyolo.platform.get_platform",
            return_value=_platform(running=False),
            autospec=True,
        ):
            allowed = cli_runner.invoke(
                app,
                [
                    "agent",
                    "config",
                    "worker",
                    "--folder",
                    str(target),
                    "--dangerously-allow-unowned",
                ],
            )

        assert denied.exit_code == 1
        assert "don't own" in denied.output
        assert allowed.exit_code == 0, allowed.output
        assert "Warning" in allowed.output
        assert load_agent("worker")["folder"] == str(target.resolve())

    def test_preserves_every_unrelated_field_and_never_runs_host_script(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        before = _setup_agent(
            tmp_config_dir,
            old,
            network_slot=42,
            grants=[{"id": "grant-1", "scope": {"repo": "safe/yolo"}}],
        )

        with (
            patch(
                "safeyolo.platform.get_platform",
                return_value=_platform(running=False),
                autospec=True,
            ),
            patch(
                "safeyolo.commands.agent._run_host_script_for_agent",
                side_effect=AssertionError("config must not execute setup"),
                autospec=True,
            ) as host_script,
        ):
            result = cli_runner.invoke(
                app, ["agent", "config", "worker", "--folder", str(new)]
            )

        assert result.exit_code == 0, result.output
        after = load_agent("worker")
        assert after == {**before, "folder": str(new.resolve())}
        host_script.assert_not_called()

    def test_preserves_unknown_nested_policy_and_comments(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        policy = tmp_config_dir / "policy.toml"
        policy.write_text(
            'version = "2.0"\n\n'
            '[hosts]\n"*" = { rate = 600 }\n\n'
            '[agents.worker]\n'
            f'folder = "{old}"\n'
            "# operator-owned annotation must survive\n"
            'future_field = "keep-me"\n\n'
            '[agents.worker.hosts."example.com"]\n'
            'methods = ["GET"]\n'
        )

        with patch(
            "safeyolo.platform.get_platform",
            return_value=_platform(running=False),
            autospec=True,
        ):
            result = cli_runner.invoke(
                app, ["agent", "config", "worker", "--folder", str(new)]
            )

        assert result.exit_code == 0, result.output
        content = policy.read_text()
        assert "# operator-owned annotation must survive" in content
        assert 'future_field = "keep-me"' in content
        assert '[agents.worker.hosts."example.com"]' in content
        assert load_agent("worker")["hosts"]["example.com"]["methods"] == ["GET"]

    def test_locked_update_does_not_clobber_concurrent_metadata(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        _setup_agent(tmp_config_dir, old)

        from safeyolo import agents_store

        real_mutate = agents_store.mutate_agent

        def concurrent_then_mutate(name, callback):
            latest = load_agent(name)
            latest["tailnet_port"] = 10443
            save_agent(name, latest)
            return real_mutate(name, callback)

        with (
            patch(
                "safeyolo.commands.agent.mutate_agent",
                side_effect=concurrent_then_mutate,
                autospec=True,
            ),
            patch(
                "safeyolo.platform.get_platform",
                return_value=_platform(running=False),
                autospec=True,
            ),
        ):
            result = cli_runner.invoke(
                app, ["agent", "config", "worker", "--folder", str(new)]
            )

        assert result.exit_code == 0, result.output
        assert load_agent("worker")["tailnet_port"] == 10443
        assert load_agent("worker")["folder"] == str(new.resolve())

    def test_ordinary_run_uses_persisted_folder_and_override_stays_transient(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        old = tmp_path / "old"
        persistent = tmp_path / "persistent"
        transient = tmp_path / "transient"
        for path in (old, persistent, transient):
            path.mkdir()
        _setup_agent(tmp_config_dir, old)

        with patch(
            "safeyolo.platform.get_platform",
            return_value=_platform(running=False),
            autospec=True,
        ):
            configured = cli_runner.invoke(
                app,
                ["agent", "config", "worker", "--folder", str(persistent)],
            )
        assert configured.exit_code == 0, configured.output

        with (
            patch(
                "safeyolo.commands.agent._run_agent",
                return_value=0,
                autospec=True,
            ) as run_agent,
            patch(
                "safeyolo.commands.agent.associate_agent_pane", autospec=True
            ),
        ):
            ordinary = cli_runner.invoke(app, ["agent", "run", "worker"])
            transient_run = cli_runner.invoke(
                app, ["agent", "run", "worker", "--folder", str(transient)]
            )

        assert ordinary.exit_code == 0
        assert transient_run.exit_code == 0
        assert run_agent.call_args_list[0].kwargs["folder_override"] is None
        assert run_agent.call_args_list[1].kwargs["folder_override"] == str(transient)
        assert load_agent("worker")["folder"] == str(persistent.resolve())

    def test_run_host_script_cannot_restore_stale_concurrent_folder(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        """The supported long-running writer must update only host_script."""
        old = tmp_path / "old"
        new = tmp_path / "new"
        old.mkdir()
        new.mkdir()
        script = tmp_path / "new-setup.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        before = _setup_agent(
            tmp_config_dir,
            old,
            network_slot=23,
            tailnet_port=10443,
            grants=[{"id": "grant-1", "scope": {"repo": "safe/yolo"}}],
        )

        def interleaved_config(**_kwargs):
            def set_folder(current):
                current["folder"] = str(new.resolve())

            changed, _ = mutate_agent("worker", set_folder)
            assert changed

        with (
            patch(
                "safeyolo.commands.agent._run_host_script_for_agent",
                side_effect=interleaved_config,
                autospec=True,
            ),
            patch(
                "safeyolo.commands.agent._run_agent",
                return_value=0,
                autospec=True,
            ),
            patch(
                "safeyolo.commands.agent.associate_agent_pane", autospec=True
            ),
        ):
            result = cli_runner.invoke(
                app,
                ["agent", "run", "worker", "--host-script", str(script)],
            )

        assert result.exit_code == 0, result.output
        after = load_agent("worker")
        assert after == {
            **before,
            "folder": str(new.resolve()),
            "host_script": str(script.resolve()),
        }

    def test_run_host_script_does_not_recreate_concurrently_removed_agent(
        self, cli_runner, tmp_config_dir, tmp_path
    ):
        folder = tmp_path / "project"
        folder.mkdir()
        script = tmp_path / "setup.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        _setup_agent(tmp_config_dir, folder)

        with (
            patch(
                "safeyolo.commands.agent._run_host_script_for_agent",
                side_effect=lambda **_kwargs: remove_agent("worker"),
                autospec=True,
            ),
            patch(
                "safeyolo.commands.agent._run_agent",
                return_value=0,
                autospec=True,
            ) as run_agent,
        ):
            result = cli_runner.invoke(
                app,
                ["agent", "run", "worker", "--host-script", str(script)],
            )

        assert result.exit_code == 1
        assert "was removed while its host script was running" in result.output
        assert load_agent("worker") == {}
        run_agent.assert_not_called()
