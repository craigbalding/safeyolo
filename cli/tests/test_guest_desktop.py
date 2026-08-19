"""Contract tests for SafeYolo's staged guest desktop launcher."""

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "cli/src/safeyolo/guest-desktop.sh"
ALPINE_BROWSER_BUILDER = (
    REPO_ROOT / "contrib/alpine-browser/build-alpine-browser-rootfs.sh"
)


def test_guest_desktop_shell_is_valid() -> None:
    result = subprocess.run(
        ["/bin/bash", "-n", str(LAUNCHER)], capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr


def test_guest_desktop_reports_missing_rootfs_capabilities(tmp_path: Path) -> None:
    result = subprocess.run(
        ["/bin/bash", str(LAUNCHER), "check"],
        env={"PATH": str(tmp_path), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 127
    assert "desktop capability unavailable" in result.stderr
    assert "Xvfb" in result.stderr
    assert "x11vnc" in result.stderr
    assert "websockify" in result.stderr
    assert "window manager" in result.stderr
    assert "noVNC web assets" in result.stderr


def test_guest_desktop_binds_vnc_and_novnc_to_loopback() -> None:
    source = LAUNCHER.read_text()

    assert "-listen 127.0.0.1" in source
    assert '"127.0.0.1:${NOVNC_PORT}"' in source
    assert '"127.0.0.1:${VNC_PORT}"' in source
    assert "hostname -I" not in source


def test_guest_browser_uses_direct_chromium_contract_and_safeyolo_proxy() -> None:
    source = LAUNCHER.read_text()

    assert "for browser in chromium chromium-browser google-chrome" in source
    assert "command -v chrome" not in source
    assert 'args+=("--proxy-server=${proxy}")' in source
    assert "SafeYolo MITM Proxy" in source


def test_graphical_rootfs_does_not_embed_desktop_orchestration() -> None:
    source = ALPINE_BROWSER_BUILDER.read_text()

    assert "guest-desktop" in source
    assert "cat > \"$TREE/usr/local/bin/startvnc\"" not in source
    assert "cat > \"$TREE/usr/local/bin/chrome\"" not in source
