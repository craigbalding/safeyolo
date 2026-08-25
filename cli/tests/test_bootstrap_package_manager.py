"""Regression tests for #353 — bootstrap preflight package-manager dispatch.

Previously `safeyolo bootstrap` hardcoded `dpkg-query` and only enumerated
missing packages under apt. Fedora / Alpine / Arch users saw
`missing_apt_deps: []` on completely bare hosts and a mid-build failure
when `safeyolo build` tried to invoke `skopeo` that was not installed.

The refactor introduces per-package-manager package maps and dispatches
package-presence queries to the appropriate tool. This test pins the
detection, install-line rendering, and mapping behaviour without needing
a real host of each distro.
"""

from unittest.mock import patch

import pytest

from safeyolo.commands.bootstrap import (
    LINUX_BUILD_DEPS,
    _detect_package_manager,
    _install_command,
    _missing_deps,
    _package_installed,
)


class TestDetectPackageManager:
    def test_returns_none_on_non_linux(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Darwin"
        )
        assert _detect_package_manager() is None

    @pytest.mark.parametrize(
        "tool,expected",
        [
            ("dpkg-query", "apt"),
            ("rpm", "dnf"),
            ("apk", "apk"),
            ("pacman", "pacman"),
        ],
    )
    def test_dispatches_by_first_available_tool(self, monkeypatch, tool, expected):
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Linux"
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == tool else None,
        )
        assert _detect_package_manager() == expected

    def test_apt_wins_over_others_when_multiple_present(self, monkeypatch):
        """apt is checked first, mirroring the historical assumption."""
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Linux"
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.shutil.which",
            lambda name: f"/usr/bin/{name}",
        )
        assert _detect_package_manager() == "apt"


class TestInstallCommand:
    """Every supported package manager renders an operator-ready command."""

    def test_apt_uses_apt_get(self):
        assert _install_command("apt", ["skopeo", "umoci"]) == (
            "sudo apt-get install -y skopeo umoci"
        )

    def test_dnf_uses_dnf(self):
        assert _install_command("dnf", ["skopeo", "umoci"]) == (
            "sudo dnf install -y skopeo umoci"
        )

    def test_apk_uses_apk_add(self):
        assert _install_command("apk", ["skopeo", "umoci"]) == (
            "sudo apk add skopeo umoci"
        )

    def test_pacman_flags_aur_note(self):
        cmd = _install_command("pacman", ["skopeo", "umoci"])
        assert cmd.startswith("sudo pacman -S --needed skopeo umoci")
        assert "AUR" in cmd

    def test_unknown_pm_falls_back_to_annotated_list(self):
        assert _install_command("unknown", ["skopeo"]) == "# unknown package manager; install: skopeo"


class TestPackageMap:
    def test_apt_keeps_full_debian_set(self):
        assert "mmdebstrap" in LINUX_BUILD_DEPS["apt"]

    def test_non_apt_omits_mmdebstrap(self):
        """mmdebstrap is Debian-only — omitted for rpm/apk/pacman."""
        for pm in ("dnf", "apk", "pacman"):
            assert "mmdebstrap" not in LINUX_BUILD_DEPS[pm], pm

    def test_every_pm_has_the_core_prereqs(self):
        core = {"skopeo", "umoci", "acl", "jq", "rsync", "tmux"}
        for pm, deps in LINUX_BUILD_DEPS.items():
            missing = core - set(deps)
            assert not missing, f"{pm} missing core prereqs: {missing}"


class TestMissingDeps:
    def test_non_linux_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Darwin"
        )
        assert _missing_deps() == ([], None)

    def test_unknown_pm_returns_empty(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Linux"
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.shutil.which", lambda name: None
        )
        assert _missing_deps() == ([], None)

    def test_all_installed_returns_empty_list_with_pm(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Linux"
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "dpkg-query" else None,
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._package_installed",
            lambda pm, pkg: True,
        )
        missing, pm = _missing_deps()
        assert missing == []
        assert pm == "apt"

    def test_partial_install_reports_the_missing_subset(self, monkeypatch):
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.system", lambda: "Linux"
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.shutil.which",
            lambda name: f"/usr/bin/{name}" if name == "rpm" else None,
        )
        # Simulate Fedora with only `jq` installed.
        installed = {"jq"}
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._package_installed",
            lambda pm, pkg: pkg in installed,
        )
        missing, pm = _missing_deps()
        assert pm == "dnf"
        assert "jq" not in missing
        for pkg in LINUX_BUILD_DEPS["dnf"]:
            if pkg != "jq":
                assert pkg in missing


class TestPackageInstalledDispatch:
    """`_package_installed` calls the right query command per manager."""

    def _record_run(self):
        calls: list[list[str]] = []

        class _R:
            def __init__(self, rc):
                self.returncode = rc
                self.stdout = "install ok installed" if rc == 0 else ""

        def _run(argv, *a, **kw):
            calls.append(argv)
            # Pretend the first positional (the query tool) always succeeds
            # so the dispatch is the only thing under test.
            return _R(0)

        return calls, _run

    def test_apt_calls_dpkg_query(self):
        calls, run = self._record_run()
        with patch("safeyolo.commands.bootstrap.subprocess.run", side_effect=run):
            assert _package_installed("apt", "skopeo") is True
        assert calls == [["dpkg-query", "-W", "-f=${Status}", "skopeo"]]

    def test_dnf_calls_rpm_q(self):
        calls, run = self._record_run()
        with patch("safeyolo.commands.bootstrap.subprocess.run", side_effect=run):
            assert _package_installed("dnf", "skopeo") is True
        assert calls == [["rpm", "-q", "skopeo"]]

    def test_apk_calls_apk_info(self):
        calls, run = self._record_run()
        with patch("safeyolo.commands.bootstrap.subprocess.run", side_effect=run):
            assert _package_installed("apk", "skopeo") is True
        assert calls == [["apk", "info", "-e", "skopeo"]]

    def test_pacman_calls_pacman_q(self):
        calls, run = self._record_run()
        with patch("safeyolo.commands.bootstrap.subprocess.run", side_effect=run):
            assert _package_installed("pacman", "skopeo") is True
        assert calls == [["pacman", "-Q", "skopeo"]]
