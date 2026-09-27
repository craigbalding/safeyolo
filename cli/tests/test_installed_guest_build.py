"""Exercise the installed CLI's build against a separate source checkout."""

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _source_checkout(path: Path, marker: str) -> None:
    guest = path / "guest"
    guest.mkdir(parents=True)
    script = guest / "build-all.sh"
    script.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'out="$(dirname "$0")/out/rootfs-tree/etc"\n'
        'mkdir -p "$out"\n'
        f"printf '%s\\n' {marker} > \"$out/source\"\n"
    )
    script.chmod(0o755)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux rootfs install boundary")
def test_installed_cli_builds_from_selected_checkout(tmp_path):
    """A wheel-installed CLI executes the pinned script and installs its output."""
    if not shutil.which("uv") or not shutil.which("sudo") or not shutil.which("rsync"):
        pytest.skip("uv, sudo and rsync are required for the installed build")

    venv = tmp_path / "venv"
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
    env = os.environ.copy()
    # Use dependencies from the test environment without importing its
    # source-installed safeyolo package ahead of the wheel under test.
    env["PYTHONPATH"] = f"{installed_site}:{sysconfig.get_path('purelib')}"
    env.pop("OUTPUT_DIR", None)
    cli = venv / "bin" / "safeyolo"
    origin = subprocess.run(
        [str(venv / "bin/python"), "-c", "import safeyolo; print(safeyolo.__file__)"],
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert Path(origin.stdout.strip()).is_relative_to(installed_site)

    selected = tmp_path / "source-r"
    other = tmp_path / "harness"
    _source_checkout(selected, "selected")
    _source_checkout(other, "other")
    config = tmp_path / "config"
    env["SAFEYOLO_CONFIG_DIR"] = str(config)
    try:
        built = subprocess.run(
            [str(cli), "build", "--source-checkout", str(selected)],
            cwd=other,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert built.returncode == 0, built.stdout + built.stderr
        assert (config / "share/rootfs-tree/etc/source").read_text() == "selected\n"
        assert (config / "share/rootfs-tree").stat().st_uid == 100000

        missing = tmp_path / "missing-source"
        failed = subprocess.run(
            [str(cli), "build", "--source-checkout", str(missing)],
            cwd=other,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert failed.returncode == 1
        assert "Cannot find guest/build-all.sh in" in failed.stdout
        assert str(missing) in failed.stdout
        assert (config / "share/rootfs-tree/etc/source").read_text() == "selected\n"
    finally:
        if config.exists():
            subprocess.run(
                ["sudo", "-n", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(config)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
