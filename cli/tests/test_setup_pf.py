"""Tests for `safeyolo setup pf` — static pf.conf anchor hook install.

These tests exercise the privilege-tightening switch from runtime append to
one-time static install:

  - The hook install is idempotent (re-running is a no-op).
  - The install refuses to modify pf.conf when it's in a partial / conflicting
    state, rather than silently rewriting it.
  - The anchor file is created empty but valid when missing.
  - Runtime is not responsible for installing the hook; the setup command is.
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from safeyolo.commands import setup as setup_mod


# ---------------------------------------------------------------------------
# _pf_conf_state — the decision function for idempotency / safety.
# ---------------------------------------------------------------------------


class TestPfConfState:
    @pytest.fixture()
    def pf_conf(self, tmp_path, monkeypatch):
        """Point the setup module at a sandboxed pf.conf in tmp_path."""
        conf = tmp_path / "pf.conf"
        anchors_dir = tmp_path / "pf.anchors"
        anchors_dir.mkdir()
        monkeypatch.setattr(setup_mod, "_PF_CONF_PATH", conf)
        monkeypatch.setattr(setup_mod, "_PF_ANCHORS_DIR", anchors_dir)
        return conf

    def _hook_lines(self):
        """Helper: same anchor/load lines the module would compute."""
        return setup_mod._pf_hook_lines("com.safeyolo")

    def test_absent_when_hook_missing(self, pf_conf):
        pf_conf.write_text("# stock pf.conf\nscrub-anchor \"com.apple/*\"\n")
        assert setup_mod._pf_conf_state("com.safeyolo") == "absent"

    def test_present_when_both_hook_lines_exist(self, pf_conf):
        anchor_line, load_line = self._hook_lines()
        pf_conf.write_text(
            'scrub-anchor "com.apple/*"\n'
            f"{anchor_line}\n"
            f"{load_line}\n"
        )
        assert setup_mod._pf_conf_state("com.safeyolo") == "present"

    def test_partial_when_only_anchor_line(self, pf_conf):
        anchor_line, _ = self._hook_lines()
        pf_conf.write_text(f"{anchor_line}\n")
        state = setup_mod._pf_conf_state("com.safeyolo")
        assert state.startswith("partial"), state

    def test_partial_when_only_load_line(self, pf_conf):
        _, load_line = self._hook_lines()
        pf_conf.write_text(f"{load_line}\n")
        state = setup_mod._pf_conf_state("com.safeyolo")
        assert state.startswith("partial"), state

    def test_conflict_when_load_points_elsewhere(self, pf_conf):
        pf_conf.write_text(
            'load anchor "com.safeyolo" from "/tmp/evil-anchor"\n'
        )
        state = setup_mod._pf_conf_state("com.safeyolo")
        # Either partial (no anchor decl) or conflict (different load path).
        assert state.startswith(("partial", "conflict")), state
        assert "com.safeyolo" in state

    def test_missing_file(self, pf_conf):
        # File does not exist (no write)
        assert pf_conf.exists() is False
        state = setup_mod._pf_conf_state("com.safeyolo")
        assert state.startswith("missing"), state


# ---------------------------------------------------------------------------
# _install_pf_hook — idempotency + safety.
# ---------------------------------------------------------------------------


class TestInstallPfHook:
    @pytest.fixture()
    def sandbox(self, tmp_path, monkeypatch):
        conf = tmp_path / "pf.conf"
        anchors_dir = tmp_path / "pf.anchors"
        anchors_dir.mkdir()
        monkeypatch.setattr(setup_mod, "_PF_CONF_PATH", conf)
        monkeypatch.setattr(setup_mod, "_PF_ANCHORS_DIR", anchors_dir)

        # Replace the `sudo tee` call with a direct file write in tests, so we
        # don't require sudo in CI. We mirror the contract: `sudo tee PATH`
        # with stdin=new_content.
        def fake_run(cmd, **kwargs):
            assert cmd[0:2] == ["sudo", "tee"], cmd
            Path(cmd[2]).write_text(kwargs["input"])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("safeyolo.commands.setup.subprocess.run", fake_run)
        return conf

    def test_adds_hook_when_absent(self, sandbox):
        sandbox.write_text("# stock pf.conf\nscrub-anchor \"com.apple/*\"\n")
        changed, msg = setup_mod._install_pf_hook("com.safeyolo")
        assert changed is True
        text = sandbox.read_text()
        anchor_line, load_line = setup_mod._pf_hook_lines("com.safeyolo")
        assert anchor_line in text
        assert load_line in text
        # Original content preserved.
        assert 'scrub-anchor "com.apple/*"' in text

    def test_is_idempotent(self, sandbox):
        sandbox.write_text("# stock pf.conf\n")
        setup_mod._install_pf_hook("com.safeyolo")
        after_first = sandbox.read_text()

        changed, msg = setup_mod._install_pf_hook("com.safeyolo")
        assert changed is False
        assert "already" in msg.lower()
        # File contents unchanged on second run — no duplicate lines.
        assert sandbox.read_text() == after_first
        assert after_first.count('anchor "com.safeyolo"') == 2  # "anchor" + "load anchor"

    def test_refuses_on_partial_state(self, sandbox):
        # Only the `anchor` line is present; load line is missing.
        sandbox.write_text('anchor "com.safeyolo"\n')
        with pytest.raises(RuntimeError) as exc:
            setup_mod._install_pf_hook("com.safeyolo")
        assert "Refusing to modify" in str(exc.value)
        # pf.conf unchanged.
        assert sandbox.read_text() == 'anchor "com.safeyolo"\n'

    def test_refuses_on_conflict(self, sandbox):
        sandbox.write_text('load anchor "com.safeyolo" from "/tmp/evil"\n')
        with pytest.raises(RuntimeError) as exc:
            setup_mod._install_pf_hook("com.safeyolo")
        assert "Refusing to modify" in str(exc.value)

    def test_appends_trailing_newline_before_hook(self, sandbox):
        # No trailing newline on existing content — _install_pf_hook must
        # not produce "stuff" + "anchor..." on the same line.
        sandbox.write_text('scrub-anchor "com.apple/*"')  # no \n
        setup_mod._install_pf_hook("com.safeyolo")
        text = sandbox.read_text()
        # The scrub-anchor line is complete (terminated) before the hook.
        assert 'scrub-anchor "com.apple/*"\n' in text
        assert '"com.apple/*"anchor' not in text

    def test_test_anchor_variant(self, sandbox):
        sandbox.write_text("# stock pf.conf\n")
        setup_mod._install_pf_hook("com.safeyolo-test")
        text = sandbox.read_text()
        anchor_line, load_line = setup_mod._pf_hook_lines("com.safeyolo-test")
        assert anchor_line in text
        assert load_line in text


# ---------------------------------------------------------------------------
# _ensure_empty_anchor_file
# ---------------------------------------------------------------------------


class TestEnsureEmptyAnchorFile:
    @pytest.fixture()
    def sandbox(self, tmp_path, monkeypatch):
        anchors_dir = tmp_path / "pf.anchors"
        anchors_dir.mkdir()
        monkeypatch.setattr(setup_mod, "_PF_ANCHORS_DIR", anchors_dir)

        def fake_run(cmd, **kwargs):
            assert cmd[0:2] == ["sudo", "tee"], cmd
            Path(cmd[2]).write_text(kwargs["input"])
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        monkeypatch.setattr("safeyolo.commands.setup.subprocess.run", fake_run)
        return anchors_dir

    def test_creates_when_missing(self, sandbox):
        changed, msg = setup_mod._ensure_empty_anchor_file("com.safeyolo")
        assert changed is True
        anchor_file = sandbox / "com.safeyolo"
        assert anchor_file.exists()
        assert "SafeYolo anchor com.safeyolo" in anchor_file.read_text()

    def test_skips_when_present(self, sandbox):
        (sandbox / "com.safeyolo").write_text("# existing content\n")
        changed, msg = setup_mod._ensure_empty_anchor_file("com.safeyolo")
        assert changed is False
        # Does not overwrite.
        assert (sandbox / "com.safeyolo").read_text() == "# existing content\n"


# ---------------------------------------------------------------------------
# `safeyolo setup pf` end-to-end via CliRunner
# ---------------------------------------------------------------------------


class TestSetupPfCommand:
    @pytest.fixture()
    def darwin(self, monkeypatch):
        monkeypatch.setattr("platform.system", lambda: "Darwin")

    @pytest.fixture()
    def sandbox(self, tmp_path, monkeypatch, darwin):
        conf = tmp_path / "pf.conf"
        anchors_dir = tmp_path / "pf.anchors"
        anchors_dir.mkdir()
        conf.write_text("# stock pf.conf\n")
        monkeypatch.setattr(setup_mod, "_PF_CONF_PATH", conf)
        monkeypatch.setattr(setup_mod, "_PF_ANCHORS_DIR", anchors_dir)

        def fake_run(cmd, **kwargs):
            if cmd[0:2] == ["sudo", "tee"]:
                Path(cmd[2]).write_text(kwargs["input"])
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            raise AssertionError(f"unexpected subprocess call: {cmd}")

        monkeypatch.setattr("safeyolo.commands.setup.subprocess.run", fake_run)
        return conf, anchors_dir

    def test_installs_com_safeyolo_hook(self, cli_runner, sandbox):
        from safeyolo.cli import app
        conf, anchors_dir = sandbox
        result = cli_runner.invoke(app, ["setup", "pf"])
        assert result.exit_code == 0, result.output
        anchor_line, load_line = setup_mod._pf_hook_lines("com.safeyolo")
        text = conf.read_text()
        assert anchor_line in text
        assert load_line in text
        assert (anchors_dir / "com.safeyolo").exists()

    def test_installs_test_anchor_with_flag(self, cli_runner, sandbox):
        from safeyolo.cli import app
        conf, anchors_dir = sandbox
        result = cli_runner.invoke(app, ["setup", "pf", "--test"])
        assert result.exit_code == 0, result.output
        anchor_line, load_line = setup_mod._pf_hook_lines("com.safeyolo-test")
        text = conf.read_text()
        assert anchor_line in text
        assert load_line in text
        assert (anchors_dir / "com.safeyolo-test").exists()

    def test_rerunning_is_idempotent(self, cli_runner, sandbox):
        from safeyolo.cli import app
        conf, _ = sandbox
        cli_runner.invoke(app, ["setup", "pf"])
        first = conf.read_text()
        result = cli_runner.invoke(app, ["setup", "pf"])
        assert result.exit_code == 0
        assert conf.read_text() == first
        # No duplicate hook block.
        _, load_line = setup_mod._pf_hook_lines("com.safeyolo")
        assert first.count(load_line) == 1
        assert first.count("SafeYolo VM isolation") == 1

    def test_fails_cleanly_on_partial_state(self, cli_runner, sandbox):
        from safeyolo.cli import app
        conf, _ = sandbox
        conf.write_text('anchor "com.safeyolo"\n')  # missing load line
        result = cli_runner.invoke(app, ["setup", "pf"])
        assert result.exit_code == 1
        assert "Refusing" in result.output or "partial" in result.output

    def test_non_darwin_is_no_op(self, cli_runner, monkeypatch, tmp_path):
        monkeypatch.setattr("platform.system", lambda: "Linux")
        from safeyolo.cli import app
        result = cli_runner.invoke(app, ["setup", "pf"])
        assert result.exit_code == 0
        assert "macOS-only" in result.output
