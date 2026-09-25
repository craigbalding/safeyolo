"""Installed-wheel guest startup preparation."""

import os
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_wheel_prepares_guest_share_without_checkout(tmp_path):
    wheel_dir = tmp_path / "dist"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    installed = tmp_path / "isolated" / "site-packages"
    with zipfile.ZipFile(next(wheel_dir.glob("*.whl"))) as archive:
        archive.extractall(installed)

    config = tmp_path / "config"
    key = config / "data" / "vm_ssh_key"
    key.parent.mkdir(parents=True)
    key.write_text("test private key")
    key.with_suffix(".pub").write_text("ssh-ed25519 test")

    script = """
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from safeyolo import vm

installed = Path(sys.argv[1])
assert Path(vm.__file__).resolve().is_relative_to(installed)
assert not (Path(vm.__file__).resolve().parents[3] / "guest").exists()
share = vm.prepare_config_share("wheel-agent", "/workspace")
assert (share / "guest-sudo").is_file()
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(installed)],
        cwd=tmp_path,
        env={**os.environ, "SAFEYOLO_CONFIG_DIR": str(config)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    staged = config / "agents" / "wheel-agent" / "config-share" / "guest-sudo"
    assert staged.read_bytes() == (REPO_ROOT / "guest" / "rootfs" / "safeyolo-sudo").read_bytes()
    assert staged.stat().st_mode & 0o777 == 0o755
