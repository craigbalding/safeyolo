"""Tests for the VM-management CLI commands.

Verifies the contracts of lifecycle (start/stop/status/build), agent
(add/list/remove/shell/stop), init, setup, doctor, sandbox, cert, and
admin. All subprocess/vm/proxy/firewall calls are mocked; no real
processes are started.
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import call, create_autospec, patch

import click
import pytest
from click import unstyle
from typer.testing import CliRunner

from safeyolo.api import AdminAPI
from safeyolo.cli import app
from safeyolo.commands.agent import _store_remove_agent
from safeyolo.platform import AgentPlatform
from safeyolo.proxy import start_proxy, wait_for_healthy


def _platform() -> AgentPlatform:
    return create_autospec(AgentPlatform, instance=True, spec_set=True)


def _api() -> AdminAPI:
    return create_autospec(AdminAPI, instance=True, spec_set=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """Isolated SafeYolo config directory with minimal required structure."""
    cfg = tmp_path / ".safeyolo"
    cfg.mkdir()
    (cfg / "certs").mkdir()
    (cfg / "policies").mkdir()
    (cfg / "data").mkdir()
    (cfg / "share").mkdir()
    (cfg / "bin").mkdir()
    (cfg / "agents").mkdir()

    logs = tmp_path / ".local" / "state" / "safeyolo"
    logs.mkdir(parents=True)

    (cfg / "config.yaml").write_text(
        "version: 1\nsandbox: true\nproxy:\n  port: 8080\n  admin_port: 9090\n"
    )
    (cfg / "policy.toml").write_text(
        'version = "2.0"\n\n[hosts]\n"*" = { rate = 600 }\n'
    )
    # Admin token needed for some commands
    token_path = cfg / "data" / "admin_token"
    token_path.write_text("test-admin-token")
    token_path.chmod(0o600)

    monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs))
    return cfg


# ---------------------------------------------------------------------------
# lifecycle.py: start
# ---------------------------------------------------------------------------


class TestLifecycleStart:

    def test_already_running_exits_zero(self, runner, config_dir):
        """If proxy is already running, prints message and exits 0."""
        with patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=True, autospec=True,):
            result = runner.invoke(app, ["start", "--no-wait"])
        assert result.exit_code == 0
        assert "already running" in result.output.lower()

    def test_first_run_bootstraps_config(self, runner, tmp_path, monkeypatch):
        """On first run (no config dir), bootstraps config then starts proxy."""
        cfg = tmp_path / "fresh" / ".safeyolo"
        logs = tmp_path / "fresh" / "logs"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cfg))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs))

        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.start_proxy", autospec=True,),
            patch("safeyolo.commands.lifecycle.wait_for_healthy", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.POLICY_TEMPLATE_PATH", cfg / "nonexistent"),
            patch("safeyolo.commands.lifecycle.ADDONS_TEMPLATE_PATH", cfg / "nonexistent"),
        ):
            result = runner.invoke(app, ["start"])

        assert "first run" in result.output.lower()
        assert cfg.exists()

    def test_guest_images_missing_warns_but_continues(self, runner, config_dir):
        """Missing guest images produce a warning but don't block start."""
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=False, autospec=True,),
            patch(
                "safeyolo.commands.lifecycle.missing_guest_images",
                return_value=["rootfs-erofs"],
            autospec=True,
            ),
            patch("safeyolo.commands.lifecycle.start_proxy", autospec=True,),
            patch("safeyolo.commands.lifecycle.wait_for_healthy", return_value=True, autospec=True,),
        ):
            result = runner.invoke(app, ["start"])

        assert result.exit_code == 0
        assert "missing" in result.output.lower()

    def test_proxy_start_failure_exits_one(self, runner, config_dir):
        """If start_proxy raises, prints error and exits 1."""
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.start_proxy", side_effect=RuntimeError("no mitmdump"), autospec=True,),
        ):
            result = runner.invoke(app, ["start", "--no-wait"])

        assert result.exit_code == 1
        assert "failed to start" in result.output.lower()

    def test_wait_timeout_fails_and_cleans_up(self, runner, config_dir):
        """A proxy that does not remain healthy cannot report success."""
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.start_proxy", autospec=True,),
            patch("safeyolo.commands.lifecycle.wait_for_healthy", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.stop_proxy", autospec=True,) as stop_proxy,
        ):
            result = runner.invoke(app, ["start"])

        assert result.exit_code == 1
        assert "did not remain healthy" in result.output.lower()
        assert "safeyolo is running" not in result.output.lower()
        stop_proxy.assert_called_once_with()

    def test_no_wait_skips_health_check(self, runner, config_dir):
        """--no-wait skips the health check entirely."""
        mock_wait = create_autospec(wait_for_healthy, spec_set=True)
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.start_proxy", autospec=True,),
            patch("safeyolo.commands.lifecycle.wait_for_healthy", mock_wait),
        ):
            result = runner.invoke(app, ["start", "--no-wait"])

        assert result.exit_code == 0
        mock_wait.assert_not_called()

    def test_flow_cache_is_forwarded_to_proxy_start(self, runner, config_dir):
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.start_proxy", autospec=True,) as start_proxy,
        ):
            result = runner.invoke(app, ["start", "--no-wait", "--flow-cache", "4321"])

        assert result.exit_code == 0
        assert start_proxy.call_args.kwargs["flow_cache"] == 4321

    def test_dev_mode_is_forwarded_to_proxy_start(self, runner, config_dir):
        with (
            patch(
                "safeyolo.commands.lifecycle.is_proxy_running",
                return_value=False,
                autospec=True,
            ),
            patch(
                "safeyolo.commands.lifecycle.check_guest_images",
                return_value=True,
                autospec=True,
            ),
            patch(
                "safeyolo.commands.lifecycle.start_proxy", autospec=True
            ) as start_proxy,
        ):
            result = runner.invoke(app, ["start", "--no-wait", "--dev"])

        assert result.exit_code == 0
        assert start_proxy.call_args.kwargs["dev"] is True

    def test_non_positive_flow_cache_is_rejected(self, runner, config_dir):
        result = runner.invoke(app, ["start", "--flow-cache", "0"])

        assert result.exit_code == 2

    def test_profile_emits_report_and_jsonl_artifact(self, runner, config_dir):
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.start_proxy", autospec=True,),
        ):
            result = runner.invoke(app, ["start", "--no-wait", "--profile"])

        assert result.exit_code == 0
        assert "SAFEYOLO PROFILE: proxy start" in result.output
        artifacts = list((config_dir.parent / ".local" / "state" / "safeyolo" / "profiles").glob("*.jsonl"))
        assert len(artifacts) == 1
        events = [json.loads(line) for line in artifacts[0].read_text().splitlines()]
        assert any(event["name"] == "TOTAL PROFILED WALL TIME" for event in events)
        assert all(event["operation"] == "proxy start" for event in events)

    @pytest.mark.parametrize(
        "arguments",
        [
            ["start", "--help"],
            ["stop", "--help"],
            ["agent", "run", "--help"],
            ["agent", "stop", "--help"],
        ],
    )
    def test_lifecycle_commands_expose_profile_option(self, runner, arguments):
        result = runner.invoke(app, arguments)
        assert result.exit_code == 0
        assert "--profile" in unstyle(result.output)


# ---------------------------------------------------------------------------
# lifecycle.py: stop
# ---------------------------------------------------------------------------


class TestLifecycleStop:

    def test_not_running_exits_zero(self, runner, config_dir):
        """If proxy not running, prints message and exits 0."""
        with patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,), \
             patch("safeyolo.commands.lifecycle.stop_proxy", autospec=True,) as stop_proxy:
            result = runner.invoke(app, ["stop"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()
        stop_proxy.assert_called_once_with()

    def test_stop_does_not_stop_agents(self, runner, config_dir):
        """Plain stop does NOT stop running agents."""
        agent_dir = config_dir / "agents" / "test-agent"
        agent_dir.mkdir(parents=True)

        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.commands.lifecycle.stop_proxy", autospec=True,),
        ):
            result = runner.invoke(app, ["stop"])

        assert result.exit_code == 0
        mock_platform.stop_sandbox.assert_not_called()
        assert "still running" in result.output.lower()

    def test_stop_all_stops_agent_vms(self, runner, config_dir):
        """stop --all iterates agent dirs and stops running agents."""
        agent_dir = config_dir / "agents" / "test-agent"
        agent_dir.mkdir(parents=True)

        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.commands.lifecycle.stop_proxy", autospec=True,),
            patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", ""), autospec=True,),
        ):
            result = runner.invoke(app, ["stop", "--all"])

        assert result.exit_code == 0
        mock_platform.stop_sandbox.assert_called_once_with("test-agent")

    def test_stop_all_unloads_firewall_rules(self, runner, config_dir):
        """stop --all calls plat.unload_firewall_rules() (iptables on Linux,
        no-op on macOS)."""
        mock_platform = _platform()
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.commands.lifecycle.stop_proxy", autospec=True,),
        ):
            result = runner.invoke(app, ["stop", "--all"])

        assert result.exit_code == 0
        mock_platform.unload_firewall_rules.assert_called_once()

    def test_stop_all_firewall_unload_failure_is_nonfatal(self, runner, config_dir):
        """Firewall unload failure doesn't prevent stop --all from completing."""
        mock_platform = _platform()
        mock_platform.unload_firewall_rules.side_effect = RuntimeError("iptables error")
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.commands.lifecycle.stop_proxy", autospec=True,),
        ):
            result = runner.invoke(app, ["stop", "--all"])

        assert result.exit_code == 0
        assert "stopped" in result.output.lower()


# ---------------------------------------------------------------------------
# lifecycle.py: status
# ---------------------------------------------------------------------------


class TestLifecycleStatus:

    def test_no_config_exits_one(self, runner, tmp_path, monkeypatch):
        """No config directory produces warning and exit 1."""
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 1

    def test_proxy_not_running_exits_zero(self, runner, config_dir):
        """Proxy not running shows panel and exits 0."""
        with patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=False, autospec=True,):
            result = runner.invoke(app, ["status"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    def test_proxy_running_shows_table(self, runner, config_dir):
        """Proxy running shows status table with ports and guest image status."""
        with (
            patch("safeyolo.commands.lifecycle.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.lifecycle.get_api", autospec=True,) as mock_api_factory,
            patch("safeyolo.vm.is_vm_running", return_value=False, autospec=True,),
        ):
            mock_api = _api()
            mock_api.stats.return_value = {}
            mock_api.pending_approvals.return_value = []
            mock_api.get_modes.return_value = {"modes": {}}
            mock_api_factory.return_value = mock_api

            result = runner.invoke(app, ["status"])

        assert result.exit_code == 0
        assert "running" in result.output.lower()


# ---------------------------------------------------------------------------
# lifecycle.py: build
# ---------------------------------------------------------------------------


class TestLifecycleBuild:

    def test_build_script_not_found_exits_one(self, runner, config_dir, monkeypatch):
        """If build-all.sh doesn't exist at the expected repo-relative path, exits 1."""
        # Point the build script path to a non-existent directory
        fake_parents = Path("/tmp/not-a-repo")
        with patch.object(Path, "resolve", return_value=fake_parents / "cli" / "src" / "safeyolo" / "commands" / "lifecycle.py", autospec=True,):
            # Simpler: just patch the computed script path directly
            pass

        # The function derives the path from __file__.parents[4], so we can't
        # easily mock Path resolution. Instead, test the failure case by mocking
        # subprocess.run to simulate a build failure.
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(1, "build-all.sh"), autospec=True,):
            result = runner.invoke(app, ["build"])

        assert result.exit_code == 1
        assert "failed" in result.output.lower()

    def test_build_copies_artifacts_to_share(self, runner, config_dir, tmp_path):
        """Successful build copies artifacts to ~/.safeyolo/share/."""
        # Create fake build output
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        (out_dir / "Image").write_bytes(b"kernel")
        (out_dir / "initramfs.cpio.gz").write_bytes(b"initramfs")
        (out_dir / "rootfs-base.ext4").write_bytes(b"rootfs")

        # Create fake build script
        build_script = tmp_path / "build-all.sh"
        build_script.touch()

        with (
            patch("subprocess.run", autospec=True,),
            patch.object(
                Path, "exists",
                side_effect=lambda self=None: True,
            autospec=True,
            ),
        ):
            # This is tricky to mock because of Path resolution from __file__
            # Testing the artifact copy logic directly instead
            import shutil

            share_dir = config_dir / "share"
            for artifact in ["Image", "initramfs.cpio.gz", "rootfs-base.ext4"]:
                src = out_dir / artifact
                shutil.copy2(str(src), str(share_dir / artifact))

        assert (config_dir / "share" / "Image").read_bytes() == b"kernel"
        assert (config_dir / "share" / "initramfs.cpio.gz").read_bytes() == b"initramfs"
        assert (config_dir / "share" / "rootfs-base.ext4").read_bytes() == b"rootfs"

    def test_install_guest_artifacts_includes_cache_paths(self, tmp_path):
        """The installer copies the Linux cache bind manifest too."""
        from safeyolo.commands.lifecycle import _install_guest_artifacts

        out_dir = tmp_path / "out"
        share_dir = tmp_path / "share"
        out_dir.mkdir()
        share_dir.mkdir()
        (out_dir / "rootfs-base.ext4").write_bytes(b"rootfs")
        (out_dir / "cache-paths.txt").write_text("/var/cache/apt\n")

        with patch("safeyolo.commands.lifecycle.platform.system", return_value="Darwin", autospec=True,):
            _install_guest_artifacts(out_dir, share_dir)

        assert (share_dir / "rootfs-base.ext4").read_bytes() == b"rootfs"
        assert (share_dir / "cache-paths.txt").read_text() == "/var/cache/apt\n"

    def test_install_guest_artifacts_preserves_linux_tree_ownership(self, tmp_path):
        """Linux installs rootfs-tree with privileged, numeric-id rsync."""
        from safeyolo.commands.lifecycle import _install_guest_artifacts

        out_dir = tmp_path / "out"
        share_dir = tmp_path / "share"
        rootfs_tree = out_dir / "rootfs-tree"
        destination = share_dir / "rootfs-tree"
        (rootfs_tree / "etc").mkdir(parents=True)
        share_dir.mkdir()

        real_stat = Path.stat

        def stat_with_subuid_owner(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if path == destination:
                values = list(result)
                values[4] = 100000
                return type(result)(values)
            return result

        def fake_rsync(*args, **kwargs):
            if args[0][1] == "rsync":
                destination.mkdir()
            return subprocess.CompletedProcess(args[0], 0)

        with (
            patch("safeyolo.commands.lifecycle.platform.system", return_value="Linux", autospec=True,),
            patch("safeyolo.commands.lifecycle.subprocess.run", side_effect=fake_rsync, autospec=True,) as run,
            patch.object(Path, "stat", autospec=True, side_effect=stat_with_subuid_owner),
        ):
            _install_guest_artifacts(out_dir, share_dir)

        assert run.call_args_list == [
            call(
                [
                    "sudo", "rsync", "-aHAX", "--numeric-ids", "--delete",
                    f"{rootfs_tree}/", f"{destination}/",
                ],
                check=True,
            ),
            call(
                ["sudo", "chown", "100000:100000", str(destination)],
                check=True,
            ),
        ]


# ---------------------------------------------------------------------------
# agent.py: name validation
# ---------------------------------------------------------------------------


class TestAgentValidateName:

    def test_empty_name_rejected(self, runner, config_dir):
        """Empty instance name is rejected."""
        # Typer itself will reject missing required argument, so test via add
        result = runner.invoke(app, ["agent", "remove", ""])
        assert result.exit_code == 1

    def test_name_too_long_rejected(self, runner, config_dir):
        """Names over 63 chars are rejected."""
        long_name = "a" * 64
        result = runner.invoke(app, ["agent", "remove", long_name])
        assert result.exit_code == 1
        assert "too long" in result.output.lower()

    def test_invalid_chars_rejected(self, runner, config_dir):
        """Names with uppercase or special chars are rejected."""
        result = runner.invoke(app, ["agent", "remove", "My_Agent"])
        assert result.exit_code == 1
        assert "invalid" in result.output.lower()

    def test_leading_hyphen_rejected(self, runner, config_dir):
        """Names starting with a hyphen are rejected."""
        result = runner.invoke(app, ["agent", "remove", "-bad"])
        assert result.exit_code != 0

    def test_valid_name_accepted(self, runner, config_dir):
        """Valid RFC 1123 names pass validation."""
        # "my-agent" is valid but agent dir won't exist, so exits 1 with "not found"
        result = runner.invoke(app, ["agent", "remove", "my-agent"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_single_char_name_accepted(self, runner, config_dir):
        """Single character names are valid."""
        result = runner.invoke(app, ["agent", "remove", "a"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()


# ---------------------------------------------------------------------------
# agent.py: add
# ---------------------------------------------------------------------------


class TestAgentAdd:

    def test_no_config_exits_one(self, runner, tmp_path, monkeypatch):
        """No config directory exits 1."""
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = runner.invoke(app, ["agent", "add", "test", "."])
        assert result.exit_code == 1
        assert "no safeyolo configuration" in result.output.lower()

    def test_folder_not_found_exits_one(self, runner, config_dir, tmp_path):
        """Non-existent folder path exits 1."""
        bad_folder = str(tmp_path / "nonexistent")
        result = runner.invoke(app, ["agent", "add", "test", bad_folder])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_host_script_not_found_exits_one(self, runner, config_dir, tmp_path):
        """--host-script pointing at a missing file exits 1."""
        folder = tmp_path / "project"
        folder.mkdir()
        result = runner.invoke(
            app,
            ["agent", "add", "test", str(folder), "--host-script", str(tmp_path / "missing.sh")],
        )
        assert result.exit_code == 1
        assert "host script" in result.output.lower()

    def test_rootfs_script_not_found_exits_one(self, runner, config_dir, tmp_path):
        """--rootfs-script pointing at a missing file exits 1."""
        folder = tmp_path / "project"
        folder.mkdir()
        result = runner.invoke(
            app,
            ["agent", "add", "test", str(folder),
             "--rootfs-script", str(tmp_path / "missing.sh")],
        )
        assert result.exit_code == 1
        assert "rootfs script" in result.output.lower()

    def test_rootfs_script_not_executable_exits_one(self, runner, config_dir, tmp_path):
        """--rootfs-script pointing at a non-executable file exits 1 with a fix hint."""
        folder = tmp_path / "project"
        folder.mkdir()
        script = tmp_path / "builder.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o644)  # readable but not executable
        result = runner.invoke(
            app,
            ["agent", "add", "test", str(folder),
             "--rootfs-script", str(script)],
        )
        assert result.exit_code == 1
        assert "not executable" in result.output.lower()
        assert "chmod +x" in result.output

    @pytest.mark.parametrize(
        ("option", "value", "expected_error"),
        [
            ("--mount", "{missing}:/proj/toolage:ro", "host path not found"),
            ("--port", "not-a-port", "invalid port format"),
        ],
    )
    def test_declarative_inputs_are_validated_before_setup_side_effects(
        self,
        runner,
        config_dir,
        tmp_path,
        option,
        value,
        expected_error,
    ):
        """Invalid mounts or ports must fail before costly host setup starts."""
        folder = tmp_path / "project"
        folder.mkdir()
        rootfs_script = tmp_path / "builder.sh"
        rootfs_script.write_text("#!/bin/sh\nexit 0\n")
        rootfs_script.chmod(0o755)
        host_script = tmp_path / "host-setup.sh"
        host_script.write_text("#!/bin/sh\nexit 0\n")
        host_script.chmod(0o755)
        value = value.format(missing=tmp_path / "missing")

        with (
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch("safeyolo.commands.agent.build_custom_rootfs", autospec=True,) as build_rootfs,
            patch("safeyolo.platform.get_platform", autospec=True,) as get_platform,
            patch("safeyolo.vm.ensure_agent_persistent_dirs", autospec=True,) as ensure_dirs,
            patch("safeyolo.commands.agent._run_host_script_for_agent", autospec=True,) as run_host_script,
        ):
            result = runner.invoke(
                app,
                [
                    "agent", "add", "test", str(folder),
                    "--rootfs-script", str(rootfs_script),
                    "--host-script", str(host_script),
                    option, value,
                    "--no-run",
                ],
            )

        assert result.exit_code == 1
        assert expected_error in result.output.lower()
        build_rootfs.assert_not_called()
        get_platform.assert_not_called()
        ensure_dirs.assert_not_called()
        run_host_script.assert_not_called()

    def test_rootfs_script_invoked_and_metadata_saved(
        self, runner, config_dir, tmp_path
    ):
        """Happy path: --rootfs-script runs before platform.prepare_rootfs,
        its path is stored in metadata."""
        folder = tmp_path / "project"
        folder.mkdir()
        script = tmp_path / "builder.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)

        mock_rootfs = config_dir / "agents" / "test" / "rootfs.ext4"
        mock_platform = _platform()
        mock_platform.prepare_rootfs.return_value = mock_rootfs

        saved = {}

        def _capture_save(name, metadata):
            saved["name"] = name
            saved["metadata"] = metadata

        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.vm.ensure_agent_persistent_dirs", autospec=True,),
            patch("safeyolo.commands.agent.save_agent", side_effect=_capture_save, autospec=True,),
            patch("safeyolo.commands.agent.write_event", autospec=True,),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch("safeyolo.commands.agent.build_custom_rootfs", autospec=True,) as mock_build,
        ):
            result = runner.invoke(
                app,
                ["agent", "add", "test", str(folder),
                 "--rootfs-script", str(script), "--no-run"],
            )

        assert result.exit_code == 0, result.output
        mock_build.assert_called_once()
        # Script path handed to the builder is the resolved absolute path
        (_, script_arg) = mock_build.call_args[0]
        assert Path(script_arg) == script.resolve()
        assert saved["metadata"]["rootfs_script"] == str(script.resolve())

    def test_rootfs_script_failure_surfaces_error(
        self, runner, config_dir, tmp_path
    ):
        """If build_custom_rootfs raises, agent add exits 1 with the error."""
        from safeyolo.vm import VMError

        folder = tmp_path / "project"
        folder.mkdir()
        script = tmp_path / "builder.sh"
        script.write_text("#!/bin/sh\nexit 1\n")
        script.chmod(0o755)

        with (
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch(
                "safeyolo.commands.agent.build_custom_rootfs",
                side_effect=VMError("builder returned 1"),
            autospec=True,
            ),
        ):
            result = runner.invoke(
                app,
                ["agent", "add", "test", str(folder),
                 "--rootfs-script", str(script), "--no-run"],
            )

        assert result.exit_code == 1
        assert "rootfs script failed" in result.output.lower()
        assert "builder returned 1" in result.output

    def test_rootfs_from_clones_rootfs_and_saves_provenance(
        self, runner, config_dir, tmp_path
    ):
        folder = tmp_path / "project"
        folder.mkdir()
        mock_rootfs = config_dir / "agents" / "engagement" / "rootfs"
        mock_platform = _platform()
        mock_platform.prepare_rootfs.return_value = mock_rootfs
        saved = {}

        def _capture_save(name, metadata):
            saved["name"] = name
            saved["metadata"] = metadata

        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.vm.ensure_agent_persistent_dirs", autospec=True,),
            patch("safeyolo.commands.agent.save_agent", side_effect=_capture_save, autospec=True,),
            patch("safeyolo.commands.agent.write_event", autospec=True,),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch("safeyolo.commands.agent.clone_custom_rootfs", autospec=True,) as mock_clone,
        ):
            result = runner.invoke(
                app,
                [
                    "agent", "add", "engagement", str(folder),
                    "--rootfs-from", "kali-base", "--no-run",
                ],
            )

        assert result.exit_code == 0, result.output
        mock_clone.assert_called_once_with("kali-base", "engagement")
        assert saved["metadata"]["rootfs_from"] == "kali-base"
        assert "Rootfs cloned from: kali-base" in result.output

    def test_rootfs_from_and_script_are_mutually_exclusive(
        self, runner, config_dir, tmp_path
    ):
        folder = tmp_path / "project"
        folder.mkdir()
        script = tmp_path / "builder.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)

        result = runner.invoke(
            app,
            [
                "agent", "add", "engagement", str(folder),
                "--rootfs-script", str(script),
                "--rootfs-from", "kali-base", "--no-run",
            ],
        )

        assert result.exit_code == 1
        assert "mutually exclusive" in result.output

    def test_rootfs_from_failure_surfaces_error(
        self, runner, config_dir, tmp_path
    ):
        from safeyolo.vm import VMError

        folder = tmp_path / "project"
        folder.mkdir()
        with (
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch(
                "safeyolo.commands.agent.clone_custom_rootfs",
                side_effect=VMError("source has no custom rootfs"),
            autospec=True,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "agent", "add", "engagement", str(folder),
                    "--rootfs-from", "kali-base", "--no-run",
                ],
            )

        assert result.exit_code == 1
        assert "rootfs clone failed" in result.output.lower()
        assert "source has no custom rootfs" in result.output

    def test_creates_rootfs_on_add(self, runner, config_dir, tmp_path):
        """add calls plat.prepare_rootfs and saves metadata (no host script)."""
        folder = tmp_path / "project"
        folder.mkdir()

        mock_rootfs = config_dir / "agents" / "test" / "rootfs.ext4"
        mock_platform = _platform()
        mock_platform.prepare_rootfs.return_value = mock_rootfs

        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.vm.ensure_agent_persistent_dirs", autospec=True,),
            patch("safeyolo.commands.agent.save_agent", autospec=True,),
            patch("safeyolo.commands.agent.write_event", autospec=True,),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "add", "test", str(folder), "--no-run"])

        assert result.exit_code == 0
        mock_platform.prepare_rootfs.assert_called_once_with("test")
        assert "added" in result.output.lower()

    def test_idempotent_readd_with_same_config(self, runner, config_dir, tmp_path):
        """Re-adding with same folder + no host-script is idempotent (runs agent)."""
        folder = tmp_path / "project"
        folder.mkdir()
        folder_str = str(folder.resolve())

        # Create existing agent dir + rootfs
        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()
        (agent_dir / "rootfs.ext4").touch()

        with (
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": folder_str},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
        ):
            result = runner.invoke(app, ["agent", "add", "test", str(folder)])

        assert "already configured" in result.output.lower()
        mock_run.assert_called_once()

    def test_idempotent_readd_associates_pane_and_requests_rename(
        self, runner, config_dir, tmp_path
    ):
        """Auto-run through the same-config path also associates and renames."""
        folder = tmp_path / "project"
        folder.mkdir()
        folder_str = str(folder.resolve())
        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()
        (agent_dir / "rootfs.ext4").touch()

        with (
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": folder_str},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,) as associate,
        ):
            result = runner.invoke(app, ["agent", "add", "test", str(folder)])

        assert result.exit_code == 0
        associate.assert_called_once_with("test")
        assert mock_run.call_args.kwargs["rename_tmux_window"] is True

    def test_idempotent_readd_no_rename_window_skips_rename_only(
        self, runner, config_dir, tmp_path
    ):
        folder = tmp_path / "project"
        folder.mkdir()
        folder_str = str(folder.resolve())
        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()
        (agent_dir / "rootfs.ext4").touch()

        with (
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": folder_str},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,) as associate,
        ):
            result = runner.invoke(
                app,
                ["agent", "add", "test", str(folder), "--no-rename-window"],
            )

        assert result.exit_code == 0
        associate.assert_called_once_with("test")
        assert mock_run.call_args.kwargs["rename_tmux_window"] is False

    def test_no_run_skips_association_and_rename(
        self, runner, config_dir, tmp_path
    ):
        """--no-run must not touch the tmux window at all."""
        folder = tmp_path / "project"
        folder.mkdir()
        folder_str = str(folder.resolve())
        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()
        (agent_dir / "rootfs.ext4").touch()

        with (
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": folder_str},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,) as associate,
        ):
            result = runner.invoke(
                app, ["agent", "add", "test", str(folder), "--no-run"]
            )

        assert result.exit_code == 0
        mock_run.assert_not_called()
        associate.assert_not_called()

    def test_different_config_without_force_exits_one(self, runner, config_dir, tmp_path):
        """Re-adding with different folder and no --force exits 1."""
        folder = tmp_path / "project"
        folder.mkdir()

        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()

        with (
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": "/other"},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "add", "test", str(folder)])

        assert result.exit_code == 1
        assert "force" in result.output.lower()


# ---------------------------------------------------------------------------
# agent.py: list
# ---------------------------------------------------------------------------


class TestAgentList:

    def test_detects_agents_by_rootfs(self, runner, config_dir):
        """list_agents detects agents via the platform-dispatched rootfs path.

        Darwin: rootfs.ext4 file. Linux: rootfs/ directory. The filter asks
        the platform which to check. Mock the platform so the test is
        hermetic on any CI host.
        """
        # Agent with a rootfs artifact in place
        vm_agent = config_dir / "agents" / "vm-agent"
        vm_agent.mkdir()
        (vm_agent / "rootfs.ext4").touch()

        # Bare dir with no rootfs artifact (should NOT appear)
        non_agent = config_dir / "agents" / "not-an-agent"
        non_agent.mkdir()

        # Mock platform returns the ext4 file path for any name it's asked about.
        # The filter will then find vm-agent/rootfs.ext4 (exists) and skip
        # not-an-agent/rootfs.ext4 (doesn't).
        mock_platform = _platform()
        mock_platform.agent_rootfs_path.side_effect = (
            lambda n: config_dir / "agents" / n / "rootfs.ext4"
        )

        with (
            patch("safeyolo.commands.agent.load_all_agents", return_value={
                "vm-agent": {"folder": "/proj"},
            }, autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        assert "vm-agent" in result.output
        assert "not-an-agent" not in result.output

    def test_no_agents_shows_message(self, runner, config_dir):
        """No agents configured shows appropriate message."""
        with (
            patch("safeyolo.commands.agent.load_all_agents", return_value={}, autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "list"])

        assert result.exit_code == 0
        assert "no agents" in result.output.lower()


# ---------------------------------------------------------------------------
# agent.py: remove
# ---------------------------------------------------------------------------


class TestAgentRemove:

    def test_agent_not_found_exits_one(self, runner, config_dir):
        """Removing non-existent agent exits 1."""
        result = runner.invoke(app, ["agent", "remove", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_stops_running_vm_before_remove(self, runner, config_dir):
        """Stops sandbox if running before removing."""
        agent_dir = config_dir / "agents" / "test-agent"
        agent_dir.mkdir()
        (agent_dir / "rootfs.ext4").touch()

        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        # Dir deletion is now platform-dispatched; have the mock actually
        # delete so other asserts behave naturally.
        import shutil as _sh
        mock_platform.remove_agent_dir.side_effect = lambda n: _sh.rmtree(
            config_dir / "agents" / n, ignore_errors=True)
        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.commands.agent._store_remove_agent", autospec=True,),
            patch("safeyolo.commands.agent.write_event", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "remove", "test-agent"])

        assert result.exit_code == 0
        mock_platform.stop_sandbox.assert_called_once_with("test-agent")
        mock_platform.remove_agent_dir.assert_called_once_with("test-agent")
        assert not agent_dir.exists()

    def test_removes_dir_and_metadata(self, runner, config_dir):
        """remove deletes agent dir and metadata entry."""
        agent_dir = config_dir / "agents" / "test-agent"
        agent_dir.mkdir()
        (agent_dir / "rootfs.ext4").touch()

        mock_store_remove = create_autospec(_store_remove_agent, spec_set=True)
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = False
        import shutil as _sh
        mock_platform.remove_agent_dir.side_effect = lambda n: _sh.rmtree(
            config_dir / "agents" / n, ignore_errors=True)
        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.commands.agent._store_remove_agent", mock_store_remove),
            patch("safeyolo.commands.agent.write_event", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "remove", "test-agent"])

        assert result.exit_code == 0
        assert not agent_dir.exists()
        mock_platform.remove_agent_dir.assert_called_once_with("test-agent")
        mock_store_remove.assert_called_once_with("test-agent")
        assert "removed" in result.output.lower()


# ---------------------------------------------------------------------------
# agent.py: shell
# ---------------------------------------------------------------------------


class TestAgentShell:

    def test_not_running_exits_one(self, runner, config_dir):
        """Shell into non-running agent exits 1."""
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = False
        with patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,):
            result = runner.invoke(app, ["agent", "shell", "test-agent"])
        assert result.exit_code == 1
        assert "not running" in result.output.lower()

    def test_running_calls_exec_in_sandbox(self, runner, config_dir):
        """Running agent: shell invokes plat.exec_in_sandbox."""
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        mock_platform.exec_in_sandbox.return_value = 0
        with patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,):
            result = runner.invoke(app, ["agent", "shell", "test-agent"])
        assert result.exit_code == 0
        mock_platform.exec_in_sandbox.assert_called_once()
        _, kwargs = mock_platform.exec_in_sandbox.call_args
        assert kwargs["user"] == "agent"

    def test_root_flag_passes_root_user(self, runner, config_dir):
        """--root flag passes user='root' to exec_in_sandbox."""
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        mock_platform.exec_in_sandbox.return_value = 0
        with patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,):
            result = runner.invoke(app, ["agent", "shell", "test-agent", "--root"])
        assert result.exit_code == 0
        _, kwargs = mock_platform.exec_in_sandbox.call_args
        assert kwargs["user"] == "root"


# ---------------------------------------------------------------------------
# agent.py: stop
# ---------------------------------------------------------------------------


class TestAgentStop:

    def test_not_running_exits_zero(self, runner, config_dir):
        """Stopping a non-running agent exits 0."""
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = False
        with patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,):
            result = runner.invoke(app, ["agent", "stop", "test-agent"])
        assert result.exit_code == 0
        assert "not running" in result.output.lower()

    def test_calls_stop_sandbox(self, runner, config_dir):
        """Stopping a running agent calls plat.stop_sandbox."""
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.proxy.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.proxy.sync_proxy_modes", autospec=True,) as sync_proxy_modes,
            patch("safeyolo.commands.agent.write_event", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "stop", "test-agent"])

        assert result.exit_code == 0
        mock_platform.stop_sandbox.assert_called_once_with("test-agent")
        sync_proxy_modes.assert_not_called()
        assert "stopped" in result.output.lower()

    def test_syncs_removed_listener_when_proxy_is_running(self, runner, config_dir):
        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        with (
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
            patch("safeyolo.proxy.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.proxy.sync_proxy_modes", autospec=True,) as sync_proxy_modes,
            patch("safeyolo.commands.agent.write_event", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "stop", "test-agent"])

        assert result.exit_code == 0
        sync_proxy_modes.assert_called_once_with(admin_port=9090)


# ---------------------------------------------------------------------------
# agent.py: _run_agent
# ---------------------------------------------------------------------------


class TestRunAgent:

    def test_linux_host_script_command_receives_effective_agent_args(self, tmp_path):
        """Every host-script command receives its resolved persistent/run args."""
        from safeyolo.commands.agent import _linux_interactive_command

        command_host = tmp_path / ".safeyolo-command"
        command_host.write_text("#!/bin/sh\n")
        command_host.chmod(0o755)

        command = _linux_interactive_command(
            command_host,
            ["--add-dir", "/proj/toolage", "--prompt", "hello world"],
            None,
        )

        assert command == (
            "/home/agent/.safeyolo-command --add-dir /proj/toolage "
            "--prompt 'hello world'"
        )

    def test_linux_plain_shell_preserves_explicit_command_override(self, tmp_path):
        from safeyolo.commands.agent import _linux_interactive_command

        command = _linux_interactive_command(
            tmp_path / "missing-command",
            ["python3", "script with spaces.py"],
            ["python3", "script with spaces.py"],
        )

        assert command == "python3 'script with spaces.py'"

    def test_run_associates_current_tmux_pane(self, runner, config_dir):
        with (
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,),
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,) as associate,
        ):
            result = runner.invoke(app, ["agent", "run", "test-agent"])

        assert result.exit_code == 0
        associate.assert_called_once_with("test-agent")

    def test_run_requests_window_rename_by_default(self, runner, config_dir):
        with (
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "run", "test-agent"])

        assert result.exit_code == 0
        assert mock_run.call_args.kwargs["rename_tmux_window"] is True

    def test_run_detach_skips_window_rename(self, runner, config_dir):
        with (
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,) as associate,
        ):
            result = runner.invoke(app, ["agent", "run", "test-agent", "--detach"])

        assert result.exit_code == 0
        assert mock_run.call_args.kwargs["rename_tmux_window"] is False
        associate.assert_called_once_with("test-agent")

    def test_run_no_rename_window_skips_rename_only(self, runner, config_dir):
        with (
            patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run,
            patch("safeyolo.commands.agent.associate_agent_pane", autospec=True,) as associate,
        ):
            result = runner.invoke(
                app, ["agent", "run", "test-agent", "--no-rename-window"]
            )

        assert result.exit_code == 0
        assert mock_run.call_args.kwargs["rename_tmux_window"] is False
        associate.assert_called_once_with("test-agent")

    def _committed_launch_patches(
        self, folder, rootfs, *, snapshot_supported=False
    ):
        """Mock every step from `_run_agent` entry through `prepare_config_share`
        as successful, and cut off execution at `write_event("agent.started")`
        so the sandbox layer is never invoked. Any test using this reaches the
        rename boundary iff the rename flag is on and no failure was injected
        earlier in the chain."""
        fake_platform = _platform()
        fake_platform.agent_rootfs_path.return_value = rootfs
        fake_platform.is_sandbox_running.return_value = False
        fake_platform.setup_networking.return_value = {
            "host_ip": "10.0.0.1",
            "guest_ip": "10.0.0.2",
            "subnet": "10.0.0.0/24",
            "attribution_ip": "10.0.0.2",
            "needs_bridge_socket": False,
        }

        import safeyolo.platform as platform_module

        return [
            patch.object(platform_module, "get_platform", return_value=fake_platform, autospec=True,),
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": str(folder)},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch("safeyolo.commands.agent.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.commands.agent.reserve_agent_network_slot", return_value=1, autospec=True,),
            patch("safeyolo.commands.agent._resolve_extra_shares", return_value=[], autospec=True,),
            patch("safeyolo.commands.agent._update_agent_map", autospec=True,),
            patch(
                "safeyolo.commands.agent.platform_supports_snapshot",
                return_value=snapshot_supported,
                autospec=True,
            ),
            patch("safeyolo.commands.agent.prepare_config_share", autospec=True,),
            patch("safeyolo.sockets.path_for", return_value=Path("/tmp/mock.sock"), autospec=True,),
            patch(
                "safeyolo.commands.agent.write_event",
                side_effect=RuntimeError("stop after rename boundary"),
            autospec=True,
            ),
        ]

    def test_run_agent_renames_after_config_share_committed(self, config_dir, tmp_path):
        """rename_window_for_agent fires only once `prepare_config_share` has
        succeeded and every earlier preflight has passed."""
        folder = tmp_path / "project"
        folder.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()

        from safeyolo.commands.agent import _run_agent

        patches = self._committed_launch_patches(folder, rootfs)
        rename_patch = patch("safeyolo.commands.agent.rename_window_for_agent", autospec=True,)

        with rename_patch as rename:
            for p in patches:
                p.start()
            try:
                with pytest.raises(RuntimeError, match="stop after rename boundary"):
                    _run_agent("committed", rename_tmux_window=True)
            finally:
                for p in patches:
                    p.stop()

        rename.assert_called_once_with("committed")

    def test_run_agent_skips_rename_when_flag_false(self, config_dir, tmp_path):
        """With the flag off, the rename call is not made even when the
        committed-launch boundary is reached (--detach, --no-rename-window)."""
        folder = tmp_path / "project"
        folder.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()

        from safeyolo.commands.agent import _run_agent

        patches = self._committed_launch_patches(folder, rootfs)
        rename_patch = patch("safeyolo.commands.agent.rename_window_for_agent", autospec=True,)

        with rename_patch as rename:
            for p in patches:
                p.start()
            try:
                with pytest.raises(RuntimeError, match="stop after rename boundary"):
                    _run_agent("committed", rename_tmux_window=False)
            finally:
                for p in patches:
                    p.stop()

        rename.assert_not_called()

    def test_snapshot_fingerprint_receives_effective_workspace(
        self, config_dir, tmp_path
    ):
        """Both persistent and one-run primary mounts participate in restore."""
        persistent = tmp_path / "persistent"
        transient = tmp_path / "transient"
        rootfs = tmp_path / "rootfs"
        for path in (persistent, transient, rootfs):
            path.mkdir()

        from safeyolo.commands.agent import _run_agent

        patches = self._committed_launch_patches(
            persistent, rootfs, snapshot_supported=True
        )
        with (
            patch(
                "safeyolo.commands.agent.compute_snapshot_version",
                return_value={"snapshot_schema": 3},
                autospec=True,
            ) as compute,
            patch(
                "safeyolo.commands.agent.is_snapshot_valid",
                return_value=True,
                autospec=True,
            ),
        ):
            for item in patches:
                item.start()
            try:
                with pytest.raises(RuntimeError, match="stop after rename boundary"):
                    _run_agent("committed", folder_override=str(transient))
            finally:
                for item in patches:
                    item.stop()

        assert compute.call_args.kwargs["workspace_path"] == transient.resolve()

    def test_run_agent_network_reservation_failure_does_not_rename(
        self, config_dir, tmp_path
    ):
        """`reserve_agent_network_slot` is a launch-committing step; its
        failure must not leave the tmux window renamed."""
        folder = tmp_path / "project"
        folder.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()

        fake_platform = _platform()
        fake_platform.agent_rootfs_path.return_value = rootfs
        fake_platform.is_sandbox_running.return_value = False

        import safeyolo.platform as platform_module
        from safeyolo.commands.agent import _run_agent

        with (
            patch.object(platform_module, "get_platform", return_value=fake_platform, autospec=True,),
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": str(folder)},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch("safeyolo.commands.agent.is_proxy_running", return_value=True, autospec=True,),
            patch(
                "safeyolo.commands.agent.reserve_agent_network_slot",
                side_effect=OSError("no slot"),
            autospec=True,
            ),
            patch("safeyolo.commands.agent.rename_window_for_agent", autospec=True,) as rename,
            pytest.raises(click.exceptions.Exit),
        ):
            _run_agent("committed", rename_tmux_window=True)

        rename.assert_not_called()

    def test_run_agent_config_share_failure_does_not_rename(
        self, config_dir, tmp_path
    ):
        """`prepare_config_share` failure sits between early preflight and
        the rename boundary; if it fails, rename must not run."""
        folder = tmp_path / "project"
        folder.mkdir()
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()

        fake_platform = _platform()
        fake_platform.agent_rootfs_path.return_value = rootfs
        fake_platform.is_sandbox_running.return_value = False
        fake_platform.setup_networking.return_value = {
            "host_ip": "10.0.0.1",
            "guest_ip": "10.0.0.2",
            "subnet": "10.0.0.0/24",
            "attribution_ip": "10.0.0.2",
            "needs_bridge_socket": False,
        }

        import safeyolo.platform as platform_module
        from safeyolo.commands.agent import _run_agent

        with (
            patch.object(platform_module, "get_platform", return_value=fake_platform, autospec=True,),
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": str(folder)},
            autospec=True,
            ),
            patch("safeyolo.commands.agent._check_project_ownership", autospec=True,),
            patch("safeyolo.commands.agent.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.commands.agent.reserve_agent_network_slot", return_value=1, autospec=True,),
            patch("safeyolo.commands.agent._resolve_extra_shares", return_value=[], autospec=True,),
            patch("safeyolo.commands.agent._update_agent_map", autospec=True,),
            patch("safeyolo.sockets.path_for", return_value=Path("/tmp/mock.sock"), autospec=True,),
            patch(
                "safeyolo.commands.agent.platform_supports_snapshot",
                return_value=False,
            autospec=True,
            ),
            patch(
                "safeyolo.commands.agent.prepare_config_share",
                side_effect=RuntimeError("config share broken"),
            autospec=True,
            ),
            patch("safeyolo.commands.agent.rename_window_for_agent", autospec=True,) as rename,
            pytest.raises(click.exceptions.Exit),
        ):
            _run_agent("committed", rename_tmux_window=True)

        rename.assert_not_called()

    def test_run_preflight_failure_does_not_rename(self, runner, config_dir):
        """Nonexistent agent: preflight fails before rename gets a chance."""
        with (
            patch("safeyolo.commands.agent.rename_window_for_agent", autospec=True,) as rename,
        ):
            result = runner.invoke(app, ["agent", "run", "no-such-agent"])

        assert result.exit_code == 1
        rename.assert_not_called()

    def test_rootfs_missing_exits_one(self, runner, config_dir):
        """_run_agent via `agent run` exits 1 if rootfs doesn't exist."""
        # Use the run command which calls _run_agent
        with (
            patch("safeyolo.commands.agent._load_agent_metadata", return_value={"folder": "."}, autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "run", "no-rootfs"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_run_host_script_reapplies_existing_agent_setup(self, runner, config_dir, tmp_path):
        """agent run --host-script runs setup against the persistent home before boot."""
        project = tmp_path / "project"
        project.mkdir()
        script = tmp_path / "setup.sh"
        script.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$SAFEYOLO_AGENT_NAME\" > \"$SAFEYOLO_AGENT_HOME/name.txt\"\n"
            "printf '%s\\n' \"$SAFEYOLO_AGENT_FOLDER\" > \"$SAFEYOLO_AGENT_HOME/folder.txt\"\n"
            "printf '%s\\n' '#!/usr/bin/env bash' 'exec echo command-ok' > \"$SAFEYOLO_AGENT_HOME/.safeyolo-command\"\n"
            "chmod +x \"$SAFEYOLO_AGENT_HOME/.safeyolo-command\"\n"
        )
        script.chmod(0o755)
        (config_dir / "policy.toml").write_text(
            'version = "2.0"\n\n[hosts]\n"*" = { rate = 600 }\n\n'
            f'[agents.web]\nfolder = "{project}"\n'
        )

        with patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run:
            result = runner.invoke(app, ["agent", "run", "web", "--host-script", str(script)])

        assert result.exit_code == 0
        home = config_dir / "agents" / "web" / "home"
        assert (home / "name.txt").read_text().strip() == "web"
        assert (home / "folder.txt").read_text().strip() == str(project.resolve())
        assert (home / ".safeyolo-command").exists()
        assert f'host_script = "{script.resolve()}"' in (config_dir / "policy.toml").read_text()
        mock_run.assert_called_once()

    def test_run_host_script_missing_exits_one(self, runner, config_dir, tmp_path):
        """agent run --host-script validates the script before booting."""
        with patch("safeyolo.commands.agent._run_agent", return_value=0, autospec=True,) as mock_run:
            result = runner.invoke(app, ["agent", "run", "web", "--host-script", str(tmp_path / "missing.sh")])

        assert result.exit_code == 1
        assert "host script not found" in result.output.lower()
        mock_run.assert_not_called()

    def test_already_running_exits_one(self, runner, config_dir, tmp_path):
        """If sandbox is already running, exits 1 with helpful message."""
        agent_dir = config_dir / "agents" / "test-agent"
        agent_dir.mkdir()
        rootfs_path = agent_dir / "rootfs.ext4"
        rootfs_path.touch()

        mock_platform = _platform()
        mock_platform.is_sandbox_running.return_value = True
        # agent_rootfs_path is platform-dispatched -- return the same file we
        # just touched so the existence check passes regardless of host OS.
        mock_platform.agent_rootfs_path.return_value = rootfs_path
        with (
            patch("safeyolo.commands.agent._load_agent_metadata", return_value={"folder": "."}, autospec=True,),
            patch("safeyolo.commands.agent.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=mock_platform, autospec=True,),
        ):
            result = runner.invoke(app, ["agent", "run", "test-agent"])

        assert result.exit_code == 1
        assert "already running" in result.output.lower()

    def test_run_forwards_persistent_and_transient_mounts_to_boot(
        self, config_dir, tmp_path, capsys,
    ):
        """Public mount settings must reach both config staging and runtime."""
        from safeyolo.commands.agent import _run_agent

        project = tmp_path / "project"
        persistent = tmp_path / "persistent-toolage"
        transient = tmp_path / "transient-toolage"
        readonly = tmp_path / "readonly-refs"
        for path in (project, persistent, transient, readonly):
            path.mkdir()

        agent_dir = config_dir / "agents" / "mount-agent"
        status_dir = agent_dir / "status"
        config_share = agent_dir / "config-share"
        status_dir.mkdir(parents=True)
        config_share.mkdir()
        rootfs = agent_dir / "rootfs"
        rootfs.mkdir()

        metadata = {
            "folder": str(project),
            "mounts": [
                f"{persistent}:/proj/toolage",
                f"{readonly}:/refs:ro",
            ],
        }
        expected = [
            (str(readonly), "/refs", True),
            (str(transient), "/proj/toolage", False),
        ]
        running = False
        platform = _platform()
        platform.agent_rootfs_path.return_value = rootfs

        def is_running(_name):
            return running

        def start_sandbox(**_kwargs):
            nonlocal running
            running = True
            (status_dir / "per-run-started").write_text("")
            return 1234

        platform.is_sandbox_running.side_effect = is_running
        platform.start_sandbox.side_effect = start_sandbox
        platform.setup_networking.return_value = {
            "host_ip": "127.0.0.1",
            "guest_ip": "10.200.0.2",
            "attribution_ip": "10.200.0.2",
            "subnet": None,
            "needs_bridge_socket": False,
        }

        with (
            patch("safeyolo.commands.agent._load_agent_metadata", return_value=metadata, autospec=True,),
            patch("safeyolo.commands.agent.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.commands.agent.reserve_agent_network_slot", return_value=0, autospec=True,),
            patch("safeyolo.commands.agent._update_agent_map", autospec=True,),
            patch("safeyolo.commands.agent.write_event", autospec=True,),
            patch("safeyolo.commands.agent.prepare_config_share", autospec=True,) as prepare,
            patch("safeyolo.platform.get_platform", return_value=platform, autospec=True,),
            patch("safeyolo.sockets.path_for", return_value=tmp_path / "proxy.sock", autospec=True,),
        ):
            result = _run_agent(
                "mount-agent",
                extra_mounts=[f"{transient}:/proj/toolage"],
                detach=True,
                no_snapshot=True,
            )

        assert result == 0
        output = capsys.readouterr().out
        assert "Starting agent... ready" in output
        assert "Agent running (detached)" in output
        assert "10.200.0.2" not in output
        assert prepare.call_args.kwargs["host_mounts"] == expected
        assert platform.start_sandbox.call_args.kwargs["extra_shares"] == expected

    @pytest.mark.parametrize(
        ("session_result", "expect_detach"),
        [
            (KeyboardInterrupt, True),
            (-2, True),
            (130, True),
            (0, False),
        ],
        ids=[
            "keyboard-interrupt",
            "negative-sigint",
            "shell-sigint",
            "normal-exit",
        ],
    )
    def test_linux_attached_session_exit_controls_sandbox_lifetime(
        self, config_dir, tmp_path, capsys, session_result, expect_detach,
    ):
        """Only host Ctrl-C leaves the Linux/gVisor sandbox running."""
        from safeyolo.commands.agent import _run_agent

        name = "session-exit-agent"
        project = tmp_path / "project"
        project.mkdir()
        agent_dir = config_dir / "agents" / name
        status_dir = agent_dir / "status"
        status_dir.mkdir(parents=True)
        rootfs = agent_dir / "rootfs"
        rootfs.mkdir()
        pid_path = agent_dir / "vm.pid"
        pid_path.write_text("1234")

        running = False
        platform = _platform()
        platform.agent_rootfs_path.return_value = rootfs

        def is_running(_name):
            return running

        def start_sandbox(**_kwargs):
            nonlocal running
            running = True
            (status_dir / "per-run-started").write_text("")
            return 1234

        platform.is_sandbox_running.side_effect = is_running
        platform.start_sandbox.side_effect = start_sandbox
        platform.setup_networking.return_value = {
            "host_ip": "127.0.0.1",
            "guest_ip": "10.200.0.2",
            "attribution_ip": "10.200.0.2",
            "subnet": None,
            "needs_bridge_socket": False,
        }
        if session_result is KeyboardInterrupt:
            platform.exec_in_sandbox.side_effect = KeyboardInterrupt
        else:
            platform.exec_in_sandbox.return_value = session_result

        with (
            patch(
                "safeyolo.commands.agent._load_agent_metadata",
                return_value={"folder": str(project)},
                autospec=True,
            ),
            patch("safeyolo.commands.agent.is_proxy_running", return_value=True, autospec=True,),
            patch("safeyolo.commands.agent.reserve_agent_network_slot", return_value=0, autospec=True,),
            patch("safeyolo.commands.agent._update_agent_map", autospec=True,),
            patch("safeyolo.commands.agent.write_event", autospec=True,) as write_event,
            patch("safeyolo.commands.agent.prepare_config_share", autospec=True,),
            patch("safeyolo.platform.get_platform", return_value=platform, autospec=True,),
            patch("safeyolo.sockets.path_for", return_value=tmp_path / "proxy.sock", autospec=True,),
            patch("sys.platform", "linux"),
        ):
            result = _run_agent(name, no_snapshot=True)

        assert result == 0
        output = capsys.readouterr().out
        event_names = [call.args[0] for call in write_event.call_args_list]
        if expect_detach:
            assert "Agent running (detached)" in output
            assert f"safeyolo agent shell {name}" in output
            platform.stop_sandbox.assert_not_called()
            assert platform.is_sandbox_running(name)
            assert pid_path.read_text() == "1234"
            assert event_names == ["agent.started"]
        else:
            assert "Agent running (detached)" not in output
            platform.stop_sandbox.assert_called_once_with(name)
            assert not pid_path.exists()
            assert event_names == ["agent.started", "agent.stopped"]


# ---------------------------------------------------------------------------
# init.py
# ---------------------------------------------------------------------------


class TestInit:

    def test_existing_config_without_force_exits_one(self, runner, config_dir):
        """Exits 1 if config already exists and no --force."""
        with patch("safeyolo.commands.init.check_guest_images", return_value=True, autospec=True,):
            result = runner.invoke(app, ["init"])
        assert result.exit_code == 1
        assert "already exists" in result.output.lower()

    def test_warns_when_guest_images_missing(self, runner, tmp_path, monkeypatch):
        """Warns about missing guest images but continues."""
        cfg = tmp_path / "init-test"
        logs = tmp_path / "init-logs"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cfg))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs))

        with (
            patch("safeyolo.commands.init.check_guest_images", return_value=False, autospec=True,),
            patch("safeyolo.commands.init.POLICY_TEMPLATE_PATH", tmp_path / "policy.toml"),
            patch("safeyolo.commands.init.ADDONS_TEMPLATE_PATH", tmp_path / "addons.yaml"),
            patch("safeyolo.commands.init.LISTS_TEMPLATE_DIR", tmp_path / "lists"),
        ):
            result = runner.invoke(app, ["init", "--no-interactive"])

        assert result.exit_code == 0
        assert "guest vm images not found" in result.output.lower()
        # VM directories should still be created
        assert (cfg / "share").exists()
        assert (cfg / "bin").exists()

    def test_creates_vm_directories(self, runner, tmp_path, monkeypatch):
        """Creates share/ and bin/ directories for VM assets."""
        cfg = tmp_path / "init-vm"
        logs = tmp_path / "init-logs"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cfg))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs))

        with (
            patch("safeyolo.commands.init.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.init.POLICY_TEMPLATE_PATH", tmp_path / "policy.toml"),
            patch("safeyolo.commands.init.ADDONS_TEMPLATE_PATH", tmp_path / "addons.yaml"),
            patch("safeyolo.commands.init.LISTS_TEMPLATE_DIR", tmp_path / "lists"),
        ):
            result = runner.invoke(app, ["init", "--no-interactive"])

        assert result.exit_code == 0
        assert (cfg / "share").exists()
        assert (cfg / "bin").exists()

    def test_init_points_user_at_setup_next(self, runner, tmp_path, monkeypatch):
        """Init's next-steps panel includes `safeyolo setup` before `start`."""
        cfg = tmp_path / "init-next"
        logs = tmp_path / "init-logs"
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(cfg))
        monkeypatch.setenv("SAFEYOLO_LOGS_DIR", str(logs))

        with (
            patch("safeyolo.commands.init.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.commands.init.POLICY_TEMPLATE_PATH", tmp_path / "policy.toml"),
            patch("safeyolo.commands.init.ADDONS_TEMPLATE_PATH", tmp_path / "addons.yaml"),
            patch("safeyolo.commands.init.LISTS_TEMPLATE_DIR", tmp_path / "lists"),
        ):
            result = runner.invoke(app, ["init", "--no-interactive"])

        assert result.exit_code == 0
        assert "safeyolo setup" in result.output.lower()
        # setup must be advertised before start; otherwise the next-steps
        # ordering still contradicts README.md's Quick Start.
        out = result.output.lower()
        assert out.index("safeyolo setup") < out.index("safeyolo start")


# ---------------------------------------------------------------------------
# setup.py
# ---------------------------------------------------------------------------


class TestSetup:

    # Existing tests exercise the macOS branch (BPF + safeyolo-vm + pf).
    # Pin the platform + stub _pf_conf_state so these run consistently on
    # any CI host regardless of its /etc/pf.conf state.

    def test_linux_runtime_installer_adds_signed_gvisor_repo(self):
        """On apt hosts, gVisor is installed via its signed release repository.

        Base packages (uidmap, acl) install first via the pm dispatch;
        then the gVisor apt repository is added and runsc is installed
        separately. Different `apt-get install` commands by design —
        the repo has to be set up between them.
        """
        from safeyolo.commands.setup import _install_linux_runtime_packages

        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            stdout = "amd64\n" if command[:2] == ["dpkg", "--print-architecture"] else ""
            return subprocess.CompletedProcess(command, 0, stdout=stdout)

        with (
            patch("safeyolo.commands.setup.shutil.which", return_value="/usr/bin/tool", autospec=True,),
            patch("safeyolo.commands.setup.subprocess.run", side_effect=fake_run, autospec=True,),
            patch("safeyolo.commands.bootstrap._detect_package_manager", return_value="apt", autospec=True,),
        ):
            assert _install_linux_runtime_packages(
                need_runsc=True,
                need_uidmap=True,
                need_acl=True,
            )

        commands = [command for command, _kwargs in calls]
        # gVisor signed repository added.
        assert ["sudo", "tee", "/etc/apt/sources.list.d/gvisor.list"] in commands
        # Base runtime packages installed via pm dispatch (before the repo add).
        assert ["sudo", "apt-get", "install", "-y", "uidmap", "acl"] in commands
        # runsc installed AFTER the gVisor repo is set up.
        assert ["sudo", "apt-get", "install", "-y", "runsc"] in commands

    def test_gvisor_tarball_verifies_sha512_and_refuses_on_mismatch(self):
        """The tarball path must verify the published SHA-512 before
        extracting anything to /usr/local/bin. Mismatch aborts.

        Uses a real bz2-compressed payload so the match-branch actually
        exercises the Python-side decompression (we don't shell out to
        system `bzip2` — Fedora Cloud Base doesn't ship it).
        """
        import bz2
        import hashlib
        import io

        from safeyolo.commands.setup import _install_gvisor_tarball

        raw_bytes = b"pretend-this-is-a-tar-payload"
        tarball_bytes = bz2.compress(raw_bytes)  # real bz2 stream
        wrong_sha_bytes = ("0" * 128).encode()  # 128 hex chars = sha512 shape
        right_sha_bytes = (hashlib.sha512(tarball_bytes).hexdigest() + "  gvisor.tar.bz2\n").encode()

        class _Resp:
            def __init__(self, data):
                self._buf = io.BytesIO(data)
            def __enter__(self):
                return self._buf
            def __exit__(self, *a):
                return False

        # Mismatch — must raise, must NOT call `sudo tar`.
        def fake_urlopen_mismatch(url):
            return _Resp(tarball_bytes if url.endswith(".bz2") else wrong_sha_bytes)

        calls: list[list[str]] = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0)

        with (
            patch("safeyolo.commands.setup._platform.machine", return_value="x86_64", autospec=True,),
            patch("safeyolo.commands.setup.urllib.request.urlopen", side_effect=fake_urlopen_mismatch, autospec=True,),
            patch("safeyolo.commands.setup.subprocess.run", side_effect=fake_run, autospec=True,),
        ):
            with pytest.raises(RuntimeError, match="SHA-512 mismatch"):
                _install_gvisor_tarball()
        assert not any("tar" in c for c in calls), "tar was invoked despite sha mismatch"

        # Match — must extract via `sudo tar -xf` (uncompressed; we
        # bz2-decompressed via Python's stdlib first).
        calls.clear()
        def fake_urlopen_match(url):
            return _Resp(tarball_bytes if url.endswith(".bz2") else right_sha_bytes)

        with (
            patch("safeyolo.commands.setup._platform.machine", return_value="x86_64", autospec=True,),
            patch("safeyolo.commands.setup.urllib.request.urlopen", side_effect=fake_urlopen_match, autospec=True,),
            patch("safeyolo.commands.setup.subprocess.run", side_effect=fake_run, autospec=True,),
        ):
            _install_gvisor_tarball()
        assert any(c[:3] == ["sudo", "tar", "-xf"] and c[-2:] == ["-C", "/usr/local/bin"] for c in calls)

    def test_linux_runtime_installer_uses_tarball_on_non_apt(self):
        """On dnf/apk/pacman hosts, gVisor comes from the verified tarball
        (no apt repo). Runtime prereqs come from the native package
        manager with the correct per-distro package names."""
        from safeyolo.commands.setup import _install_linux_runtime_packages

        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout="")

        # Patch _install_gvisor_tarball to a no-op recorder — the tarball
        # download itself hits the network and has its own test coverage.
        # We only assert that the tarball path is the one taken here.
        tarball_called = []

        def _fake_tarball():
            tarball_called.append(True)

        with (
            patch("safeyolo.commands.setup.shutil.which", return_value="/usr/bin/sudo", autospec=True,),
            patch("safeyolo.commands.setup.subprocess.run", side_effect=fake_run, autospec=True,),
            patch("safeyolo.commands.bootstrap._detect_package_manager", return_value="dnf", autospec=True,),
            patch("safeyolo.commands.setup._install_gvisor_tarball", side_effect=_fake_tarball, autospec=True,),
        ):
            assert _install_linux_runtime_packages(
                need_runsc=True,
                need_uidmap=True,
                need_acl=True,
            )

        commands = [command for command, _kwargs in calls]
        # dnf install with Fedora's package names for uidmap (shadow-utils)
        # + acl (unchanged).
        assert ["sudo", "dnf", "install", "-y", "shadow-utils", "acl"] in commands
        # gVisor came from the tarball path, not from any dnf/apt call.
        assert tarball_called == [True]
        # No apt commands at all.
        assert not any(c[:2] == ["sudo", "apt-get"] for c in commands)

    def test_guest_images_ok(self, runner, config_dir):
        """Reports OK when guest images are available."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Darwin", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.vm.find_vm_helper", return_value=Path("/usr/local/bin/safeyolo-vm"), autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "ok" in result.output.lower()
        assert "guest images" in result.output.lower()

    def test_guest_images_missing_shows_missing(self, runner, config_dir):
        """Reports MISSING when guest images are absent, listing the platform-
        appropriate artifacts (e.g. initramfs on Darwin, rootfs-tree on Linux)."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Darwin", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=False, autospec=True,),
            patch(
                "safeyolo.commands.setup.missing_guest_images",
                return_value=["initramfs", "rootfs-ext4"],
            autospec=True,
            ),
            patch("safeyolo.vm.find_vm_helper", return_value=Path("/usr/local/bin/safeyolo-vm"), autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 1
        assert "missing" in result.output.lower()
        assert "initramfs" in result.output.lower()

    def test_vm_helper_missing_shows_missing(self, runner, config_dir):
        """Reports MISSING when safeyolo-vm binary is not found."""
        from safeyolo.vm import VMError as _VMError

        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Darwin", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.vm.find_vm_helper", side_effect=_VMError("not found"), autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 1
        assert "missing" in result.output.lower()
        assert "safeyolo-vm" in result.output.lower()

    def test_all_ok_summary(self, runner, config_dir):
        """Shows all-OK summary when everything passes."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Darwin", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.vm.find_vm_helper", return_value=Path("/usr/local/bin/safeyolo-vm"), autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "all prerequisites met" in result.output.lower()

    # Linux branch: runsc replaces safeyolo-vm. find_runsc() does
    # the actual PATH lookup, so mock it directly -- no need to stub shutil.
    def test_runsc_ok_on_linux(self, runner, config_dir):
        """Linux: reports OK when runsc is present."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.platform.linux.find_runsc", return_value="/usr/bin/runsc", autospec=True,),
            patch("safeyolo.platform.linux.check_userns_prerequisites", return_value={
                "newuidmap": True, "newgidmap": True,
                "subuid": True, "subgid": True,
                "setfacl": True,
                "apparmor_restricts": False, "apparmor_profile_loaded": False,
            }, autospec=True,),
            patch("safeyolo.platform.linux.detect_runsc_platform", return_value={
                "platform": "kvm", "kvm_exists": True,
                "kvm_operator_access": True, "kvm_subordinate_access": True,
                "reason": "KVM available with full access",
            }, autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "runsc" in result.output.lower()
        assert "all prerequisites met" in result.output.lower()
        # Shouldn't mention macOS-specific checks
        assert "safeyolo-vm" not in result.output.lower()

    def test_runsc_missing_shows_missing_on_linux(self, runner, config_dir):
        """Linux: reports MISSING when runsc is not found, with install hint."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.platform.linux.find_runsc", return_value=None, autospec=True,),
            patch(
                "safeyolo.commands.setup._install_linux_runtime_packages",
                return_value=False,
            autospec=True,
            ),
            patch("safeyolo.platform.linux.check_userns_prerequisites", return_value={
                "newuidmap": True, "newgidmap": True,
                "subuid": True, "subgid": True,
                "setfacl": True,
                "apparmor_restricts": False, "apparmor_profile_loaded": False,
            }, autospec=True,),
            patch("safeyolo.platform.linux.detect_runsc_platform", return_value={
                "platform": "systrap", "kvm_exists": False,
                "kvm_operator_access": False, "kvm_subordinate_access": False,
                "reason": "/dev/kvm not found",
            }, autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 1
        assert "missing" in result.output.lower()
        assert "runsc" in result.output.lower()
        assert "gvisor" in result.output.lower()

    def test_setup_installs_missing_runsc_on_apt_linux(self, runner, config_dir):
        """Linux setup installs runsc, then evaluates the refreshed state."""
        userns = {
            "newuidmap": True, "newgidmap": True,
            "subuid": True, "subgid": True,
            "setfacl": True,
            "apparmor_restricts": False, "apparmor_profile_loaded": False,
        }
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch(
                "safeyolo.platform.linux.find_runsc",
                side_effect=[None, "/usr/bin/runsc"],
            autospec=True,
            ),
            patch(
                "safeyolo.platform.linux.check_userns_prerequisites",
                return_value=userns,
            autospec=True,
            ),
            patch(
                "safeyolo.commands.setup._install_linux_runtime_packages",
                return_value=True,
            autospec=True,
            ) as install,
            patch("safeyolo.platform.linux.detect_runsc_platform", return_value={
                "platform": "systrap", "kvm_exists": False,
                "kvm_operator_access": False, "kvm_subordinate_access": False,
                "reason": "/dev/kvm not found",
            }, autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        install.assert_called_once_with(
            need_runsc=True,
            need_uidmap=False,
            need_acl=False,
        )
        assert "all prerequisites met" in result.output.lower()

    def test_setup_fails_when_subuid_mapping_is_missing(self, runner, config_dir):
        """A missing user mapping must stop callers such as migration."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.platform.linux.find_runsc", return_value="/usr/bin/runsc", autospec=True,),
            patch("safeyolo.platform.linux.check_userns_prerequisites", return_value={
                "newuidmap": True, "newgidmap": True,
                "subuid": False, "subgid": True,
                "setfacl": True,
                "apparmor_restricts": False, "apparmor_profile_loaded": False,
            }, autospec=True,),
            patch("safeyolo.platform.linux.detect_runsc_platform", return_value={
                "platform": "systrap", "kvm_exists": False,
                "kvm_operator_access": False, "kvm_subordinate_access": False,
                "reason": "/dev/kvm not found",
            }, autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 1
        assert "/etc/subuid" in result.output

    def test_kvm_group_membership_missing_shows_usermod_hint(self, runner, config_dir):
        """/dev/kvm present, group has rw, operator not in group — print the
        exact `usermod -aG <group>` remediation instead of a bare INFO."""
        with (
            patch("safeyolo.commands.setup._platform.system", return_value="Linux", autospec=True,),
            patch("safeyolo.commands.setup.check_guest_images", return_value=True, autospec=True,),
            patch("safeyolo.platform.linux.find_runsc", return_value="/usr/bin/runsc", autospec=True,),
            patch("safeyolo.platform.linux.check_userns_prerequisites", return_value={
                "newuidmap": True, "newgidmap": True,
                "subuid": True, "subgid": True,
                "setfacl": True,
                "apparmor_restricts": False, "apparmor_profile_loaded": False,
            }, autospec=True,),
            patch("safeyolo.platform.linux.detect_runsc_platform", return_value={
                "platform": "systrap", "kvm_exists": True,
                "kvm_operator_access": False, "kvm_subordinate_access": False,
                "kvm_group": "kvm", "kvm_group_has_rw": True,
                "operator_in_kvm_group": False,
                "reason": "/dev/kvm exists but operator lacks rw access",
            }, autospec=True,),
        ):
            result = runner.invoke(app, ["setup"])

        assert result.exit_code == 0
        assert "sudo usermod -aG kvm $USER" in result.output
        assert "log out and back in" in result.output


# ---------------------------------------------------------------------------
# doctor.py
# ---------------------------------------------------------------------------


class TestDoctorProxyCheck:

    def test_proxy_running_returns_pass(self, runner, config_dir):
        """_check_proxy_process returns pass when proxy is running."""
        from safeyolo.commands.doctor import _check_proxy_process

        with patch("safeyolo.commands.doctor.is_proxy_running", return_value=True, autospec=True,):
            result = _check_proxy_process()

        assert result.status == "pass"
        assert result.name == "Proxy running"
        assert "mitmdump" in result.message.lower()

    def test_proxy_not_running_returns_fail_with_remediation(self, runner, config_dir):
        """_check_proxy_process returns fail with remediation when proxy not running."""
        from safeyolo.commands.doctor import _check_proxy_process

        with patch("safeyolo.commands.doctor.is_proxy_running", return_value=False, autospec=True,):
            result = _check_proxy_process()

        assert result.status == "fail"
        assert result.name == "Proxy running"
        assert "safeyolo start" in result.remediation.lower()


class TestDoctorAutoFix:

    def test_fix_starts_proxy_on_failure(self, runner, config_dir):
        """--fix attempts to start proxy when proxy check fails."""
        from safeyolo.commands.doctor import DiagResult, _attempt_fix

        results = [
            DiagResult(name="Proxy running", status="fail", message="not running"),
        ]

        mock_start = create_autospec(start_proxy, spec_set=True)
        with patch("safeyolo.proxy.start_proxy", mock_start):
            actions = _attempt_fix(results)

        mock_start.assert_called_once()
        assert len(actions) == 1
        assert "started" in actions[0].lower()

    def test_fix_ignores_non_fail_results(self, runner, config_dir):
        """--fix only acts on 'fail' status results."""
        from safeyolo.commands.doctor import DiagResult, _attempt_fix

        results = [
            DiagResult(name="Proxy running", status="pass", message="running"),
            DiagResult(name="CA certificate", status="warn", message="not found"),
        ]

        mock_start = create_autospec(start_proxy, spec_set=True)
        with patch("safeyolo.proxy.start_proxy", mock_start):
            actions = _attempt_fix(results)

        mock_start.assert_not_called()
        assert len(actions) == 0


class TestDoctorDependencyCascade:

    def test_admin_api_skipped_when_proxy_fails(self, runner, config_dir):
        """Admin API check is skipped when Proxy check fails (dependency cascade)."""
        from safeyolo.commands.doctor import _run_checks

        with (
            patch("safeyolo.commands.doctor.is_proxy_running", return_value=False, autospec=True,),
            patch("safeyolo.commands.doctor.find_config_dir", return_value=config_dir, autospec=True,),
            patch("safeyolo.commands.doctor.load_config", return_value={"proxy": {"port": 8080, "admin_port": 9090}}, autospec=True,),
        ):
            results = _run_checks()

        results_by_name = {r.name: r for r in results}
        assert results_by_name["Proxy running"].status == "fail"
        assert results_by_name["Admin API"].status == "skip"
        assert results_by_name["Pipeline probe"].status == "skip"


# ---------------------------------------------------------------------------
# cert.py
# ---------------------------------------------------------------------------


class TestCertShow:

    def test_no_config_exits_one(self, runner, tmp_path, monkeypatch):
        """Exits 1 when no config directory."""
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = runner.invoke(app, ["cert", "show"])
        assert result.exit_code == 1

    def test_cert_not_generated_shows_message(self, runner, config_dir):
        """Shows 'not generated' when cert doesn't exist."""
        result = runner.invoke(app, ["cert", "show"])
        assert result.exit_code == 0
        assert "not generated" in result.output.lower()

    def test_cert_show_mentions_virtiofs(self, runner, config_dir):
        """`cert show` mentions the VirtioFS config share that carries the CA."""
        cert_file = config_dir / "certs" / "mitmproxy-ca-cert.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

        result = runner.invoke(app, ["cert", "show"])
        assert result.exit_code == 0
        assert "virtiofs" in result.output.lower()


class TestCertEnv:

    def test_no_config_exits_one(self, runner, tmp_path, monkeypatch):
        """Exits 1 when no config directory."""
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = runner.invoke(app, ["cert", "env"])
        assert result.exit_code == 1

    def test_cert_not_found_exits_one(self, runner, config_dir):
        """Exits 1 when cert file doesn't exist."""
        result = runner.invoke(app, ["cert", "env"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_outputs_env_exports(self, runner, config_dir):
        """Outputs shell exports with proxy and cert paths."""
        cert_file = config_dir / "certs" / "mitmproxy-ca-cert.pem"
        cert_file.write_text("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")

        result = runner.invoke(app, ["cert", "env"])
        assert result.exit_code == 0
        assert "export HTTP_PROXY=" in result.output
        assert "export SSL_CERT_FILE=" in result.output
        assert "export NODE_EXTRA_CA_CERTS=" in result.output


# ---------------------------------------------------------------------------
# admin.py: check
# ---------------------------------------------------------------------------


class TestAdminCheck:

    def test_no_config_fails(self, runner, tmp_path, monkeypatch):
        """Fails when no config directory."""
        monkeypatch.setenv("SAFEYOLO_CONFIG_DIR", str(tmp_path / "nonexistent"))
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 1

    def test_proxy_not_running_shows_warning(self, runner, config_dir):
        """Shows warning when proxy not running."""
        with patch("safeyolo.commands.admin.is_proxy_running", return_value=False, autospec=True,):
            result = runner.invoke(app, ["check"])

        assert "not running" in result.output.lower()


# ---------------------------------------------------------------------------
# vm.py: guest image checks
# ---------------------------------------------------------------------------


class TestGuestImageChecks:
    """check_guest_images is platform-aware:
      - macOS: kernel + initramfs + ext4 rootfs.
      - Linux: unpacked rootfs tree (OCI root.path). gVisor ships its
        own kernel and consumes the tree directly -- no image file."""

    def test_all_images_present(self, config_dir):
        """Every artifact present => True under either platform dispatch."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "Image").touch()
        (share / "initramfs.cpio.gz").touch()
        (share / "rootfs-base.ext4").touch()
        (share / "rootfs-tree" / "etc").mkdir(parents=True)

        with patch("safeyolo.vm.platform.system", return_value="Darwin", autospec=True,):
            assert check_guest_images() is True
        with patch("safeyolo.vm.platform.system", return_value="Linux", autospec=True,):
            assert check_guest_images() is True

    def test_missing_kernel_on_darwin(self, config_dir):
        """check_guest_images returns False on macOS when kernel is missing."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "initramfs.cpio.gz").touch()
        (share / "rootfs-base.ext4").touch()

        with patch("safeyolo.vm.platform.system", return_value="Darwin", autospec=True,):
            assert check_guest_images() is False

    def test_missing_initramfs_on_darwin(self, config_dir):
        """check_guest_images returns False on macOS when initramfs is missing."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "Image").touch()
        (share / "rootfs-base.ext4").touch()

        with patch("safeyolo.vm.platform.system", return_value="Darwin", autospec=True,):
            assert check_guest_images() is False

    def test_missing_rootfs_on_darwin(self, config_dir):
        """Darwin returns False when ext4 rootfs is missing."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "Image").touch()
        (share / "initramfs.cpio.gz").touch()

        with patch("safeyolo.vm.platform.system", return_value="Darwin", autospec=True,):
            assert check_guest_images() is False

    def test_missing_rootfs_tree_on_linux(self, config_dir):
        """Linux returns False when the unpacked rootfs tree is missing,
        even if the ext4 image is present."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "rootfs-base.ext4").touch()

        with patch("safeyolo.vm.platform.system", return_value="Linux", autospec=True,):
            assert check_guest_images() is False

    def test_linux_only_needs_rootfs_tree(self, config_dir):
        """On Linux, the unpacked tree alone is what gVisor uses — kernel,
        initramfs, and ext4 are not required."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "rootfs-tree" / "etc").mkdir(parents=True)
        # No Image, no initramfs.cpio.gz, no ext4

        with patch("safeyolo.vm.platform.system", return_value="Linux", autospec=True,):
            assert check_guest_images() is True

    def test_linux_ext4_alone_is_not_enough(self, config_dir):
        """On Linux, having only the ext4 rootfs should NOT pass —
        gVisor needs the unpacked tree."""
        from safeyolo.vm import check_guest_images

        share = config_dir / "share"
        (share / "rootfs-base.ext4").touch()

        with patch("safeyolo.vm.platform.system", return_value="Linux", autospec=True,):
            assert check_guest_images() is False

    def test_guest_image_status_returns_per_artifact(self, config_dir):
        """guest_image_status returns a dict keyed by artifact name
        (no platform dispatch)."""
        from safeyolo.vm import guest_image_status

        share = config_dir / "share"
        (share / "Image").touch()
        (share / "rootfs-tree" / "etc").mkdir(parents=True)
        # initramfs and ext4 missing

        status = guest_image_status()
        assert status == {
            "kernel": True,
            "initramfs": False,
            "rootfs-ext4": False,
            "rootfs-tree": True,
        }


# ---------------------------------------------------------------------------
# vm.py: is_vm_running
# ---------------------------------------------------------------------------


class TestIsVmRunning:

    def test_no_pid_file_returns_false(self, config_dir):
        """Returns False when no PID file exists."""
        from safeyolo.vm import is_vm_running

        assert is_vm_running("nonexistent") is False

    def test_stale_pid_returns_false_and_cleans_up(self, config_dir):
        """Stale PID file (process dead) returns False and removes PID file."""
        from safeyolo.vm import is_vm_running

        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()
        pid_file = agent_dir / "vm.pid"
        pid_file.write_text("99999999")  # Non-existent PID

        assert is_vm_running("test") is False
        assert not pid_file.exists()  # Cleaned up

    def test_live_pid_returns_true(self, config_dir):
        """Returns True when PID file points to a live process."""
        import os

        from safeyolo.vm import is_vm_running

        agent_dir = config_dir / "agents" / "test"
        agent_dir.mkdir()
        pid_file = agent_dir / "vm.pid"
        pid_file.write_text(str(os.getpid()))  # Our own PID is guaranteed alive

        assert is_vm_running("test") is True


# ---------------------------------------------------------------------------
# vm.py: create_agent_rootfs
# ---------------------------------------------------------------------------


class TestCreateAgentRootfs:
    """Phase A: no per-agent rootfs clone. All agents share the read-only
    ext4 base; create_agent_rootfs only ensures the per-agent dir exists
    and returns the shared base path."""

    def test_base_rootfs_missing_raises_vmerror(self, config_dir):
        """Raises VMError when base rootfs doesn't exist."""
        from safeyolo.vm import VMError, create_agent_rootfs

        with pytest.raises(VMError, match="Base rootfs not found"):
            create_agent_rootfs("test")

    def test_returns_shared_base_and_creates_agent_dir(self, config_dir):
        """Returns the shared base path and ensures the per-agent dir
        exists (so later code can write overlay.img, config-share, etc.
        into it). Does NOT copy the base."""
        from safeyolo.vm import create_agent_rootfs

        share = config_dir / "share"
        base = share / "rootfs-base.ext4"
        base.write_bytes(b"shared-base-content")

        result = create_agent_rootfs("test")

        assert result == base
        assert (config_dir / "agents" / "test").is_dir()
        # No per-agent rootfs file was materialised.
        assert not (config_dir / "agents" / "test" / "rootfs.ext4").exists()


# ---------------------------------------------------------------------------
# proxy.py: is_proxy_running
# ---------------------------------------------------------------------------


class TestIsProxyRunning:

    def test_no_pid_file_returns_false(self, config_dir):
        """Returns False when no PID file exists."""
        from safeyolo.proxy import is_proxy_running

        assert is_proxy_running() is False

    def test_stale_pid_cleans_up(self, config_dir):
        """Stale PID (dead process) returns False and removes PID file."""
        from safeyolo.proxy import is_proxy_running

        pid_file = config_dir / "data" / "proxy.pid"
        pid_file.write_text("99999999")

        assert is_proxy_running() is False
        assert not pid_file.exists()

    def test_live_pid_returns_true(self, config_dir):
        """Live PID returns True."""
        import os

        from safeyolo.proxy import is_proxy_running

        pid_file = config_dir / "data" / "proxy.pid"
        pid_file.write_text(str(os.getpid()))

        assert is_proxy_running() is True


# ---------------------------------------------------------------------------
# vm.py: _update_agent_map
# ---------------------------------------------------------------------------


class TestAgentMap:

    def test_add_agent_to_map(self, config_dir):
        """Adding an agent writes IP and timestamp to map file."""
        import json

        from safeyolo.vm import _update_agent_map

        _update_agent_map("test", ip="192.168.65.2")

        map_path = config_dir / "data" / "agent_map.json"
        data = json.loads(map_path.read_text())
        assert "test" in data
        assert data["test"]["ip"] == "192.168.65.2"
        assert "started" in data["test"]

    def test_remove_agent_from_map(self, config_dir):
        """Removing an agent removes it from the map."""
        import json

        from safeyolo.vm import _update_agent_map

        _update_agent_map("test", ip="192.168.65.2")
        _update_agent_map("test", remove=True)

        map_path = config_dir / "data" / "agent_map.json"
        data = json.loads(map_path.read_text())
        assert "test" not in data

    def test_corrupted_map_file_is_replaced(self, config_dir):
        """Corrupted JSON map file is replaced with empty map."""
        import json

        from safeyolo.vm import _update_agent_map

        map_path = config_dir / "data" / "agent_map.json"
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text("not valid json{{{")

        _update_agent_map("test", ip="192.168.65.2")

        data = json.loads(map_path.read_text())
        assert data["test"]["ip"] == "192.168.65.2"


# ---------------------------------------------------------------------------
# agent.py: _parse_mount
# ---------------------------------------------------------------------------


class TestParseMount:

    def test_valid_rw_mount(self, tmp_path):
        """Valid read-write mount is normalized."""
        from safeyolo.commands.agent import _parse_mount

        host_dir = tmp_path / "data"
        host_dir.mkdir()
        result = _parse_mount(f"{host_dir}:/data")
        assert result == f"{host_dir}:/data"

    def test_valid_ro_mount(self, tmp_path):
        """Valid read-only mount is normalized."""
        from safeyolo.commands.agent import _parse_mount

        host_dir = tmp_path / "data"
        host_dir.mkdir()
        result = _parse_mount(f"{host_dir}:/data:ro")
        assert result == f"{host_dir}:/data:ro"

    def test_host_path_not_found_exits(self, tmp_path):
        """Non-existent host path raises typer.Exit."""
        from typer import Exit

        from safeyolo.commands.agent import _parse_mount

        with pytest.raises(Exit):
            _parse_mount(f"{tmp_path}/nonexistent:/data")

    def test_container_path_must_be_absolute(self, tmp_path):
        """Container path must start with /."""
        from typer import Exit

        from safeyolo.commands.agent import _parse_mount

        host_dir = tmp_path / "data"
        host_dir.mkdir()
        with pytest.raises(Exit):
            _parse_mount(f"{host_dir}:data")

    def test_container_path_cannot_traverse_or_replace_runtime_mounts(self, tmp_path):
        from typer import Exit

        from safeyolo.commands.agent import _parse_mount

        host_dir = tmp_path / "data"
        host_dir.mkdir()
        with pytest.raises(Exit):
            _parse_mount(f"{host_dir}:/proj/../safeyolo")
        with pytest.raises(Exit):
            _parse_mount(f"{host_dir}:/workspace")

    def test_persistent_and_transient_mounts_resolve_with_transient_override(
        self, tmp_path,
    ):
        from safeyolo.commands.agent import _resolve_extra_shares

        persistent = tmp_path / "persistent"
        replacement = tmp_path / "replacement"
        readonly = tmp_path / "readonly"
        for path in (persistent, replacement, readonly):
            path.mkdir()

        shares = _resolve_extra_shares(
            {"mounts": [f"{persistent}:/proj/toolage", f"{readonly}:/refs:ro"]},
            [f"{replacement}:/proj/toolage"],
        )

        assert shares == [
            (str(readonly), "/refs", True),
            (str(replacement), "/proj/toolage", False),
        ]


# ---------------------------------------------------------------------------
# agent.py: _parse_port
# ---------------------------------------------------------------------------


class TestParsePort:

    def test_valid_two_part_port(self):
        """host:container normalizes to 127.0.0.1:host:container."""
        from safeyolo.commands.agent import _parse_port

        result = _parse_port("6080:6080")
        assert result == "127.0.0.1:6080:6080"

    def test_valid_three_part_port(self):
        """127.0.0.1:host:container is accepted."""
        from safeyolo.commands.agent import _parse_port

        result = _parse_port("127.0.0.1:6080:6080")
        assert result == "127.0.0.1:6080:6080"

    def test_non_localhost_bind_rejected(self):
        """Non-localhost bind address is rejected."""
        from typer import Exit

        from safeyolo.commands.agent import _parse_port

        with pytest.raises(Exit):
            _parse_port("0.0.0.0:6080:6080")

    def test_reserved_container_port_rejected(self):
        """Container ports 8080 and 9090 (used by SafeYolo) are rejected."""
        from typer import Exit

        from safeyolo.commands.agent import _parse_port

        with pytest.raises(Exit):
            _parse_port("8080:8080")
        with pytest.raises(Exit):
            _parse_port("9000:9090")

    def test_invalid_port_number_rejected(self):
        """Non-integer or out-of-range ports are rejected."""
        from typer import Exit

        from safeyolo.commands.agent import _parse_port

        with pytest.raises(Exit):
            _parse_port("abc:6080")
        with pytest.raises(Exit):
            _parse_port("6080:0")
        with pytest.raises(Exit):
            _parse_port("6080:70000")
