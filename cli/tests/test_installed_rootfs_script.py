"""Linux custom rootfs scripts use guest files from their CLI installation."""

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GUEST_FILES = (
    "install-guest-common.sh",
    "rootfs/safeyolo-guest-init",
    "rootfs/safeyolo-sudo",
)
BUILD_ROOTFS = """
from pathlib import Path
import sys
from safeyolo import vm

print(vm.__file__)
print(vm.build_custom_rootfs("source-check", Path(sys.argv[1])))
"""


def _write_probe_script(path: Path) -> Path:
    script = path / "probe.sh"
    script.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        '[ "$SAFEYOLO_GUEST_SRC_DIR" = "$EXPECTED_GUEST_DIR" ]\n'
        'test -f "$SAFEYOLO_GUEST_SRC_DIR/install-guest-common.sh"\n'
        'test -f "$SAFEYOLO_GUEST_SRC_DIR/rootfs/safeyolo-guest-init"\n'
        'test -f "$SAFEYOLO_GUEST_SRC_DIR/rootfs/safeyolo-sudo"\n'
        'mkdir -p "$SAFEYOLO_ROOTFS_OUT_TREE/etc"\n'
        'printf "%s\\n" "$SAFEYOLO_GUEST_SRC_DIR" > '
        '"$SAFEYOLO_ROOTFS_OUT_TREE/etc/guest-source"\n'
    )
    script.chmod(0o755)
    return script


@pytest.mark.skipif(sys.platform != "linux", reason="Linux rootfs-script boundary")
def test_wheel_rootfs_script_uses_installed_guest_files(tmp_path):
    wheel_dir = tmp_path / "wheel"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    wheel = next(wheel_dir.glob("safeyolo-*.whl"))
    venv = tmp_path / "venv"
    subprocess.run(
        ["uv", "venv", "--offline", "--python", sys.executable, str(venv)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    subprocess.run(
        ["uv", "pip", "install", "--offline", "--no-deps", "--python", str(venv / "bin/python"), str(wheel)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )

    installed_site = venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    installed_guest = installed_site / "safeyolo" / "guest"
    for filename in GUEST_FILES:
        assert (installed_guest / filename).read_bytes() == (REPO_ROOT / "guest" / filename).read_bytes()

    unrelated = tmp_path / "unrelated-cwd"
    (unrelated / "guest").mkdir(parents=True)
    script = _write_probe_script(tmp_path)
    env = {
        **os.environ,
        "SAFEYOLO_CONFIG_DIR": str(tmp_path / "config"),
        "EXPECTED_GUEST_DIR": str(installed_guest),
        "PYTHONPATH": f"{installed_site}{os.pathsep}{sysconfig.get_path('purelib')}",
    }
    command = [str(venv / "bin/python"), "-c", BUILD_ROOTFS, str(script)]
    result = subprocess.run(
        command, cwd=unrelated, env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert Path(result.stdout.splitlines()[0]).is_relative_to(installed_site)
    guest_source = tmp_path / "config/agents/source-check/rootfs/etc/guest-source"
    cache_paths = tmp_path / "config/agents/source-check/cache-paths.txt"
    assert guest_source.read_text() == f"{installed_guest}\n"
    cache_paths.write_text("/var/cache/apt\n")

    # A retry with incomplete guest support must leave the old rootfs intact.
    missing_file = installed_guest / "rootfs/safeyolo-guest-init"
    missing_file.unlink()
    incomplete = subprocess.run(
        command, cwd=unrelated, env=env, capture_output=True, text=True, timeout=30,
    )
    assert incomplete.returncode != 0
    assert f"Required guest support file not readable at {missing_file}" in incomplete.stderr
    assert guest_source.read_text() == f"{installed_guest}\n"
    assert cache_paths.read_text() == "/var/cache/apt\n"

    # A damaged wheel must not fall back to an unrelated guest/ in the CWD.
    shutil.rmtree(installed_guest)
    missing = subprocess.run(
        command, cwd=unrelated, env=env, capture_output=True, text=True, timeout=30,
    )
    assert missing.returncode != 0
    assert f"guest/ directory not found at {installed_guest}" in missing.stderr
    assert guest_source.read_text() == f"{installed_guest}\n"
    assert cache_paths.read_text() == "/var/cache/apt\n"


@pytest.mark.skipif(sys.platform != "linux", reason="Linux rootfs-script boundary")
def test_source_checkout_rootfs_script_uses_checkout_guest_files(tmp_path):
    script = _write_probe_script(tmp_path)
    guest = REPO_ROOT / "guest"
    env = {
        **os.environ,
        "SAFEYOLO_CONFIG_DIR": str(tmp_path / "config"),
        "EXPECTED_GUEST_DIR": str(guest),
    }
    source_probe = f"import sys; sys.path.insert(0, {str(REPO_ROOT / 'cli/src')!r})\n" + BUILD_ROOTFS
    result = subprocess.run(
        [sys.executable, "-I", "-c", source_probe, str(script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert Path(result.stdout.splitlines()[0]) == REPO_ROOT / "cli/src/safeyolo/vm.py"
    assert (tmp_path / "config/agents/source-check/rootfs/etc/guest-source").read_text() == f"{guest}\n"
