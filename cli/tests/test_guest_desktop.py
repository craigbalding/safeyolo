"""Contract tests for SafeYolo's staged guest desktop launcher."""

import shlex
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "cli/src/safeyolo/guest-desktop.sh"
ALPINE_BROWSER_BUILDER = (
    REPO_ROOT / "contrib/alpine-browser/build-alpine-browser-rootfs.sh"
)
KALI_BUILDER = REPO_ROOT / "contrib/kali-pentest/build-kali-rootfs.sh"


def test_guest_desktop_shell_is_valid() -> None:
    result = subprocess.run(
        ["/bin/bash", "-n", str(LAUNCHER)], capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr


def test_guest_desktop_reports_missing_rootfs_capabilities(tmp_path: Path) -> None:
    # The test host may itself be a SafeYolo guest with a working helper at the
    # production absolute path. Select an absent helper for this negative case.
    launcher = tmp_path / "guest-desktop"
    missing_helper = shlex.quote(str(tmp_path / "missing-guest-helper"))
    launcher.write_text(LAUNCHER.read_text().replace(
        "if ! /safeyolo/safeyolo-guest desktop-bridge check",
        f"if ! {missing_helper} desktop-bridge check",
    ))
    result = subprocess.run(
        ["/bin/bash", str(launcher), "check"],
        env={"PATH": str(tmp_path), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 127
    assert "desktop capability unavailable" in result.stderr
    assert "Xvfb" in result.stderr
    assert "x11vnc" in result.stderr
    assert "desktop bridge (/safeyolo/safeyolo-guest)" in result.stderr
    assert "window manager" in result.stderr
    assert "noVNC web assets" in result.stderr


def test_guest_desktop_binds_vnc_and_novnc_to_loopback() -> None:
    source = LAUNCHER.read_text()

    assert "-listen 127.0.0.1" in source
    assert '"127.0.0.1:${NOVNC_PORT}"' in source
    assert '"127.0.0.1:${VNC_PORT}"' in source
    assert "hostname -I" not in source


def test_fluxbox_uses_quiet_isolated_configuration() -> None:
    source = LAUNCHER.read_text()

    assert 'FLUXBOX_CONFIG_DIR=/tmp/safeyolo-fluxbox' in source
    assert "'background: unset'" in source
    assert 'fluxbox -rc "$FLUXBOX_CONFIG_DIR/init"' in source
    assert "session.screen0.workspaceNames: Apps: right-click desktop," in source
    assert "session.screen0.toolbar.visible: true" in source
    assert '$HOME/.fluxbox/overlay' not in source


def test_desktop_menu_exposes_available_terminal_and_browser() -> None:
    source = LAUNCHER.read_text()

    assert "_find_terminal()" in source
    assert "_find_browser()" in source
    assert "(Terminal) {/safeyolo/guest-desktop terminal}" in source
    assert "(Browser) {/safeyolo/guest-desktop browser about:blank}" in source
    assert '<item label="Terminal">' in source
    assert '<item label="Browser">' in source
    assert "terminal) _terminal" in source


def test_ready_desktop_refreshes_discovered_applications() -> None:
    source = LAUNCHER.read_text()
    ready_branch = source[
        source.index('if _is_ready && [ "$current" = "${width}x${height}" ]') :
        source.index('web_root="$(_find_web_root)"')
    ]

    assert 'WINDOW_MANAGER_FILE=/tmp/safeyolo-window-manager' in source
    assert "_configure_fluxbox" in ready_branch
    assert "_configure_openbox" in ready_branch
    assert "openbox --reconfigure" in ready_branch
    assert "legacy window-manager configuration; restarting" in ready_branch


def test_guest_desktop_reads_staged_host_geometry_preference() -> None:
    source = LAUNCHER.read_text()

    assert "/safeyolo/desktop-size" in source
    assert "${configured_geometry:-1280x800}" in source


def test_guest_browser_uses_direct_chromium_contract_and_safeyolo_proxy() -> None:
    source = LAUNCHER.read_text()

    assert "for candidate in chromium chromium-browser google-chrome" in source
    assert "command -v chrome" not in source
    assert 'args+=("--proxy-server=${proxy}")' in source
    assert "SafeYolo MITM Proxy" in source


def test_graphical_rootfs_does_not_embed_desktop_orchestration() -> None:
    source = ALPINE_BROWSER_BUILDER.read_text()

    assert "guest-desktop" in source
    assert "cat > \"$TREE/usr/local/bin/startvnc\"" not in source
    assert "cat > \"$TREE/usr/local/bin/chrome\"" not in source


def test_graphical_rootfs_profiles_supply_a_terminal() -> None:
    assert "xterm" in ALPINE_BROWSER_BUILDER.read_text()
    assert "xterm" in KALI_BUILDER.read_text()


def test_novnc_assets_reject_corrupt_cached_source(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "novnc-1.6.0.tar.gz").write_bytes(b"corrupt-archive")
    rootfs = tmp_path / "rootfs"
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "guest/install-novnc-assets.sh"), str(rootfs), str(cache)],
        capture_output=True, text=True, timeout=10,
    )

    assert result.returncode != 0
    assert "FAILED" in result.stdout
    assert not rootfs.exists()
