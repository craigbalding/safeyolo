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
    _UMOCI_SHA256,
    _UMOCI_VERSION,
    LINUX_BUILD_DEPS,
    _detect_package_manager,
    _ensure_umoci,
    _install_command,
    _missing_deps,
    _package_installed,
    _prepend_safeyolo_bin_to_path,
    _safeyolo_bin_dir,
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
        # umoci is intentionally excluded from the core-installable-via-pm
        # set — dnf/apk/pacman don't ship it in default repos, so
        # `_ensure_umoci()` handles it separately. See TestPackageMapUmociExclusion.
        core = {"skopeo", "acl", "jq", "rsync", "tmux"}
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


class TestPackageMapUmociExclusion:
    """umoci must live outside LINUX_BUILD_DEPS for every manager that
    doesn't ship it in a default supported repo — `_ensure_umoci()`
    handles those. Only apt keeps umoci in the map (Ubuntu / Debian
    ship it in the default repos)."""

    def test_apt_keeps_umoci(self):
        assert "umoci" in LINUX_BUILD_DEPS["apt"]

    @pytest.mark.parametrize("pm", ["dnf", "apk", "pacman"])
    def test_non_apt_omits_umoci(self, pm):
        assert "umoci" not in LINUX_BUILD_DEPS[pm], pm


class TestEnsureUmoci:
    """`_ensure_umoci()` implements the operator-supplied algorithm:
    PATH → SafeYolo bin dir → native package → pinned upstream download.
    Applies to every dnf / apk / pacman host, not just fedora-41."""

    def test_returns_on_path_when_umoci_in_path(self, monkeypatch, tmp_path):
        fake = tmp_path / "umoci"
        fake.write_text("#!/bin/sh\n")
        fake.chmod(0o755)
        monkeypatch.setattr("safeyolo.commands.bootstrap.shutil.which",
                            lambda name: str(fake) if name == "umoci" else None)
        got = _ensure_umoci("dnf")
        assert got["state"] == "on_path"
        assert got["path"] == str(fake)

    def test_returns_safeyolo_bin_when_installed_there(self, monkeypatch, tmp_config_dir):
        # PATH miss → falls to SafeYolo bin dir. Fixture already created bin/.
        (tmp_config_dir / "bin").mkdir(exist_ok=True)
        pinned = tmp_config_dir / "bin" / "umoci"
        pinned.write_text("#!/bin/sh\n")
        pinned.chmod(0o755)
        monkeypatch.setattr("safeyolo.commands.bootstrap.shutil.which", lambda name: None)
        got = _ensure_umoci("dnf")
        assert got["state"] == "safeyolo_bin"
        assert got["path"] == str(pinned)
        assert got["version"] == _UMOCI_VERSION

    def test_apt_defers_to_native_package(self, monkeypatch, tmp_config_dir):
        # PATH miss, SafeYolo bin miss, pm=apt → operator installs via apt;
        # `_ensure_umoci()` does not download.
        monkeypatch.setattr("safeyolo.commands.bootstrap.shutil.which", lambda name: None)
        got = _ensure_umoci("apt")
        assert got["state"] == "needs_native"

    def test_dnf_apk_pacman_download_when_missing(self, monkeypatch, tmp_config_dir):
        """No native package, nothing on disk → download + sha-verify + install."""
        import hashlib
        import io

        pinned_bytes = b"fake-umoci-binary-contents"
        pinned_sha = hashlib.sha256(pinned_bytes).hexdigest()

        monkeypatch.setattr("safeyolo.commands.bootstrap.shutil.which", lambda name: None)
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._UMOCI_SHA256",
            {"amd64": pinned_sha, "arm64": pinned_sha},
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.machine", lambda: "x86_64"
        )

        class _FakeResp:
            def __init__(self, data):
                self._buf = io.BytesIO(data)

            def __enter__(self):
                return self._buf

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.urlopen",
            lambda url: _FakeResp(pinned_bytes),
        )

        for pm in ("dnf", "apk", "pacman"):
            # Reset the bin dir between iterations.
            binf = tmp_config_dir / "bin" / "umoci"
            binf.unlink(missing_ok=True)

            got = _ensure_umoci(pm)
            assert got["state"] == "installed", (pm, got)
            assert got["path"] == str(binf)
            assert binf.exists()
            assert binf.read_bytes() == pinned_bytes
            assert binf.stat().st_mode & 0o111  # executable

    def test_sha_mismatch_rejects(self, monkeypatch, tmp_config_dir):
        """Downloaded bytes whose sha256 doesn't match the pin must NOT be
        installed. This is the whole reason we don't curl-pipe to shell."""
        import io

        wrong_bytes = b"tampered-with-payload"

        monkeypatch.setattr("safeyolo.commands.bootstrap.shutil.which", lambda name: None)
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._UMOCI_SHA256",
            {"amd64": "0" * 64, "arm64": "0" * 64},
        )
        monkeypatch.setattr(
            "safeyolo.commands.bootstrap._platform.machine", lambda: "x86_64"
        )

        class _FakeResp:
            def __init__(self, data):
                self._buf = io.BytesIO(data)

            def __enter__(self):
                return self._buf

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(
            "safeyolo.commands.bootstrap.urlopen",
            lambda url: _FakeResp(wrong_bytes),
        )

        got = _ensure_umoci("dnf")
        assert got["state"] == "sha_mismatch"
        # Nothing should have landed in the bin dir.
        assert not (tmp_config_dir / "bin" / "umoci").exists()

    def test_pinned_shas_are_64_char_hex(self):
        for arch, sha in _UMOCI_SHA256.items():
            assert len(sha) == 64, f"{arch} sha not sha256-shaped: {sha}"
            int(sha, 16)  # raises ValueError if non-hex


class TestPrependSafeyoloBinToPath:
    def test_prepends_and_is_idempotent(self, monkeypatch, tmp_config_dir):
        monkeypatch.setenv("PATH", "/usr/bin:/bin")
        _prepend_safeyolo_bin_to_path()
        expected_first = str(_safeyolo_bin_dir())
        assert __import__("os").environ["PATH"].split(":")[0] == expected_first
        # Idempotent: running again doesn't duplicate.
        _prepend_safeyolo_bin_to_path()
        parts = __import__("os").environ["PATH"].split(":")
        assert parts.count(expected_first) == 1
